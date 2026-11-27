package workload_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories/signingkey/signingkeytest"
	"github.com/boson-chat/auth/internal/keycrypt"
	"github.com/boson-chat/auth/internal/services/workload"
	"github.com/golang-jwt/jwt/v5"
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
	lead     = time.Hour
	ttl      = 5 * time.Minute
	secret   = "0123456789abcdef0123456789abcdef"
)

var pushrelay = config.WorkloadIdentity{Name: "pushrelay", Audiences: []string{"boson-pushrelay"}, Token: secret}

func newService(t *testing.T) (*workload.Service, *signingkeytest.MemRepository, *clock, []byte) {
	t.Helper()
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	repo := signingkeytest.New()
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	ks, err := workload.NewKeySet(repo, db.NoTx{}, workload.KeyOptions{EncryptionKey: kek, Rotation: rotation, PublishLead: lead, TokenTTL: ttl, Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	other := config.WorkloadIdentity{Name: "other", Audiences: []string{"a", "b"}, Token: "fedcba9876543210fedcba9876543210"}
	return workload.NewService(ks, "https://auth.example.com/", ttl, []config.WorkloadIdentity{pushrelay, other}, c.Now), repo, c, kek
}

func kids(set workload.JWKS) []string {
	var out []string
	for _, k := range set.Keys {
		out = append(out, k.Kid)
	}
	return out
}

// keyfunc verifies against the published JWKS, like Google does.
func keyfunc(set workload.JWKS) jwt.Keyfunc {
	return func(tk *jwt.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		for _, k := range set.Keys {
			if k.Kid != kid || k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" {
				continue
			}
			x, _ := base64.RawURLEncoding.DecodeString(k.X)
			y, _ := base64.RawURLEncoding.DecodeString(k.Y)
			return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
		}
		return nil, jwt.ErrTokenUnverifiable
	}
}

func TestMintedTokenVerifiesWithJWKS(t *testing.T) {
	svc, _, c, _ := newService(t)
	if svc.Issuer() != "https://auth.example.com/workload" {
		t.Fatalf("issuer %q", svc.Issuer())
	}
	tok, err := svc.Mint(context.Background(), pushrelay, "")
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.RegisteredClaims
	parsed, err := jwt.ParseWithClaims(tok.JWT, &claims, keyfunc(svc.Keys.JWKS()),
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer("https://auth.example.com/workload"),
		jwt.WithAudience("boson-pushrelay"), jwt.WithTimeFunc(c.Now), jwt.WithIssuedAt(), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "service:pushrelay" || claims.ID == "" || parsed.Header["typ"] != "JWT" {
		t.Fatalf("claims %+v header %v", claims, parsed.Header)
	}
	if d := claims.ExpiresAt.Sub(claims.IssuedAt.Time); d != ttl || d > 10*time.Minute {
		t.Fatalf("lifetime %s", d)
	}
	if tok.Subject != claims.Subject || tok.Audience != "boson-pushrelay" || !tok.ExpiresAt.Equal(claims.ExpiresAt.Time) {
		t.Fatalf("token %+v", tok)
	}
}

func TestMintAudiences(t *testing.T) {
	svc, _, _, _ := newService(t)
	ctx := context.Background()
	if _, err := svc.Mint(ctx, pushrelay, "boson-pushrelay"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Mint(ctx, pushrelay, "//iam.googleapis.com/other"); err != workload.ErrAudience {
		t.Fatalf("unlisted audience: %v", err)
	}
	other, err := svc.Authenticate("fedcba9876543210fedcba9876543210")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Mint(ctx, other, ""); err != workload.ErrAudience {
		t.Fatalf("no audience with two configured: %v", err)
	}
	if tok, err := svc.Mint(ctx, other, "b"); err != nil || tok.Subject != "service:other" {
		t.Fatalf("%+v %v", tok, err)
	}
}

func TestAuthenticate(t *testing.T) {
	svc, _, _, _ := newService(t)
	if w, err := svc.Authenticate(secret); err != nil || w.Name != "pushrelay" {
		t.Fatalf("%+v %v", w, err)
	}
	for _, bad := range []string{"", "x", secret + "x"} {
		if _, err := svc.Authenticate(bad); err != workload.ErrUnknownWorkload {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

func TestKeysAreES256AndEncryptedAtRest(t *testing.T) {
	svc, repo, _, kek := newService(t)
	all, _ := repo.ListAll(context.Background())
	if len(all) != 1 || all[0].Alg != "ES256" || all[0].PublicJWK["kty"] != "EC" || all[0].PublicJWK["y"] == "" {
		t.Fatalf("stored %+v", all)
	}
	kid, priv, err := svc.Keys.SigningKey()
	if err != nil || kid != all[0].KID {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	if bytes.Contains(all[0].PrivateKeyEnc, der) || bytes.Contains(all[0].PrivateKeyEnc, priv.D.Bytes()) {
		t.Fatal("private key stored in plaintext")
	}
	plain, err := keycrypt.Open(kek, all[0].PrivateKeyEnc, []byte(kid))
	if err != nil || !bytes.Equal(plain, der) {
		t.Fatalf("stored key does not decrypt to the signing key: %v", err)
	}
	set := svc.Keys.JWKS()
	if len(set.Keys) != 1 || set.Keys[0].Kid != kid || set.Keys[0].Use != "sig" {
		t.Fatalf("jwks %+v", set)
	}
}

// The successor is published PublishLead before it signs; the old key stays
// in the JWKS until its last token expired (+ lead + margin).
func TestRotationKeepsPreviousKeyPublished(t *testing.T) {
	svc, repo, c, _ := newService(t)
	ctx := context.Background()
	first, _, _ := svc.Keys.SigningKey()
	c.Add(rotation - lead - time.Minute)
	_ = svc.Keys.Ensure(ctx)
	if repo.Len() != 1 {
		t.Fatal("rotated early")
	}
	c.Add(2 * time.Minute)
	_ = svc.Keys.Ensure(ctx)
	set := kids(svc.Keys.JWKS())
	if len(set) != 2 {
		t.Fatalf("successor not published: %v", set)
	}
	if k, _, _ := svc.Keys.SigningKey(); k != first {
		t.Fatal("successor signs before the publish lead")
	}
	tok, _ := svc.Mint(ctx, pushrelay, "")
	c.Add(lead)
	_ = svc.Keys.Ensure(ctx)
	second, _, _ := svc.Keys.SigningKey()
	if second == first {
		t.Fatal("successor not signing after the lead")
	}
	// A token from the old key still verifies.
	if !slices.Contains(kids(svc.Keys.JWKS()), first) {
		t.Fatal("retired key dropped right away")
	}
	if _, err := jwt.Parse(tok.JWT, keyfunc(svc.Keys.JWKS()), jwt.WithoutClaimsValidation()); err != nil {
		t.Fatal(err)
	}
	c.Add(ttl + lead + 11*time.Minute)
	_ = svc.Keys.Ensure(ctx)
	if got := kids(svc.Keys.JWKS()); slices.Contains(got, first) || !slices.Contains(got, second) {
		t.Fatalf("after retention: %v", got)
	}
	list, err := svc.Keys.List(ctx)
	if err != nil || len(list) != 2 || list[0].State != "expired" || list[1].State != "active" || list[0].Alg != "ES256" {
		t.Fatalf("list %+v %v", list, err)
	}
}

func TestRotateNow(t *testing.T) {
	svc, _, _, _ := newService(t)
	first, _, _ := svc.Keys.SigningKey()
	kid, err := svc.Keys.Rotate(context.Background(), true)
	if err != nil || kid == first {
		t.Fatal(err)
	}
	if k, _, _ := svc.Keys.SigningKey(); k != kid {
		t.Fatal("rotate --now does not sign with the new key")
	}
	if got := kids(svc.Keys.JWKS()); !slices.Contains(got, first) {
		t.Fatalf("old key dropped: %v", got)
	}
}
