package keys_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories/signingkey/signingkeytest"
	"github.com/boson-chat/auth/internal/keycrypt"
	"github.com/boson-chat/auth/internal/services/keys"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const (
	rotation = 30 * 24 * time.Hour
	lead     = 15 * time.Minute
	maxTTL   = 15 * time.Minute
)

func newService(t *testing.T) (keys.KeyServiceImpl, *signingkeytest.MemRepository, *clock, []byte) {
	t.Helper()
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	repo := signingkeytest.New()
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc, err := keys.NewKeyService(repo, db.NoTx{}, keys.Options{
		EncryptionKey: kek, Rotation: rotation, PublishLead: lead, MaxTokenTTL: maxTTL, Now: c.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, repo, c, kek
}

func kids(set keys.JWKS) []string {
	var out []string
	for _, k := range set.Keys {
		out = append(out, k.Kid)
	}
	return out
}

func TestFirstStartCreatesOneKey(t *testing.T) {
	ctx := context.Background()
	svc, repo, _, _ := newService(t)
	if _, _, err := svc.SigningKey(ctx); err == nil {
		t.Fatal("expected no key before Ensure")
	}
	for range 3 {
		if err := svc.Ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if repo.Len() != 1 {
		t.Fatalf("Ensure created %d keys, want 1", repo.Len())
	}
	kid, priv, err := svc.SigningKey(ctx)
	if err != nil || len(priv) == 0 {
		t.Fatalf("SigningKey: %v", err)
	}
	set := svc.JWKS(ctx)
	if len(set.Keys) != 1 || set.Keys[0].Kid != kid || set.Keys[0].Kty != "OKP" || set.Keys[0].Crv != "Ed25519" || set.Keys[0].Alg != "EdDSA" {
		t.Fatalf("unexpected JWKS %+v", set)
	}
}

func TestPrivateKeyEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	svc, repo, _, kek := newService(t)
	if err := svc.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	all, _ := repo.ListAll(ctx)
	kid, priv, _ := svc.SigningKey(ctx)
	k := all[0]
	if bytes.Contains(k.PrivateKeyEnc, priv.Seed()) {
		t.Fatal("seed stored in plaintext")
	}
	seed, err := keycrypt.Open(kek, k.PrivateKeyEnc, []byte(kid))
	if err != nil || !bytes.Equal(seed, priv.Seed()) {
		t.Fatalf("stored key does not decrypt to the signing key: %v", err)
	}
}

func TestScheduledRotation(t *testing.T) {
	ctx := context.Background()
	svc, _, c, _ := newService(t)
	if err := svc.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	first, _, _ := svc.SigningKey(ctx)

	// Not due yet.
	c.Add(rotation - lead - time.Minute)
	_ = svc.Ensure(ctx)
	if n := len(svc.JWKS(ctx).Keys); n != 1 {
		t.Fatalf("rotated early: %d keys", n)
	}

	// Within the publish lead: successor is published but doesn't sign yet.
	c.Add(2 * time.Minute)
	_ = svc.Ensure(ctx)
	set := kids(svc.JWKS(ctx))
	if len(set) != 2 {
		t.Fatalf("successor not published: %v", set)
	}
	if kid, _, _ := svc.SigningKey(ctx); kid != first {
		t.Fatalf("successor signs before its activation time")
	}
	second := set[1]
	if _, err := svc.PublicKey(ctx, second); err != nil {
		t.Fatalf("pending key not verifiable: %v", err)
	}

	// After activation the successor signs, the old key still verifies.
	c.Add(lead)
	_ = svc.Ensure(ctx)
	if kid, _, _ := svc.SigningKey(ctx); kid != second {
		t.Fatalf("signing with %s, want successor %s", kid, second)
	}
	if _, err := svc.PublicKey(ctx, first); err != nil {
		t.Fatalf("retired key must verify for max TTL: %v", err)
	}

	// Long after max TTL the old key leaves the JWKS.
	c.Add(maxTTL + 11*time.Minute)
	_ = svc.Ensure(ctx)
	if got := kids(svc.JWKS(ctx)); len(got) != 1 || got[0] != second {
		t.Fatalf("JWKS after retention = %v, want only %s", got, second)
	}
	if _, err := svc.PublicKey(ctx, first); err == nil {
		t.Fatal("expired key still verifies")
	}
}

func TestManualRotate(t *testing.T) {
	ctx := context.Background()
	svc, _, c, _ := newService(t)
	_ = svc.Ensure(ctx)
	first, _, _ := svc.SigningKey(ctx)

	kid, err := svc.Rotate(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if cur, _, _ := svc.SigningKey(ctx); cur != first {
		t.Fatal("non-immediate rotate must wait for the publish lead")
	}
	c.Add(lead)
	if cur, _, _ := svc.SigningKey(ctx); cur != kid {
		t.Fatalf("after lead signing with %s, want %s", cur, kid)
	}

	now, err := svc.Rotate(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if cur, _, _ := svc.SigningKey(ctx); cur != now {
		t.Fatal("immediate rotate must sign right away")
	}
	if len(svc.JWKS(ctx).Keys) != 3 {
		t.Fatalf("all keys within retention must stay published, got %v", kids(svc.JWKS(ctx)))
	}
	list, _ := svc.List(ctx)
	states := map[string]string{}
	for _, k := range list {
		states[k.KID] = k.State
	}
	if states[first] != "retired" || states[kid] != "retired" || states[now] != "active" {
		t.Fatalf("states = %v", states)
	}
}

func TestReplicaPicksUpNewKey(t *testing.T) {
	ctx := context.Background()
	a, repo, c, kek := newService(t)
	_ = a.Ensure(ctx)
	b, _ := keys.NewKeyService(repo, db.NoTx{}, keys.Options{EncryptionKey: kek, Rotation: rotation, PublishLead: lead, MaxTokenTTL: maxTTL, Now: c.Now})
	_ = b.Ensure(ctx)
	if repo.Len() != 1 {
		t.Fatalf("second replica created a key: %d", repo.Len())
	}
	kid, err := a.Rotate(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	c.Add(time.Minute) // past the reload throttle
	if _, err := b.PublicKey(ctx, kid); err != nil {
		t.Fatalf("replica b should reload on unknown kid: %v", err)
	}
}

func TestWrongEncryptionKeyFails(t *testing.T) {
	ctx := context.Background()
	a, repo, c, _ := newService(t)
	_ = a.Ensure(ctx)
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	b, _ := keys.NewKeyService(repo, db.NoTx{}, keys.Options{EncryptionKey: other, Rotation: rotation, PublishLead: lead, MaxTokenTTL: maxTTL, Now: c.Now})
	if err := b.Ensure(ctx); err == nil {
		t.Fatal("loading keys with the wrong KEK must fail loudly")
	}
}
