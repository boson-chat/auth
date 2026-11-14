package token_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories/signingkey/signingkeytest"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/perm"
	"github.com/boson-chat/auth/internal/services/keys"
	"github.com/boson-chat/auth/internal/services/token"
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

const issuer = "https://auth.example.test"

func setup(t *testing.T) (token.TokenServiceImpl, keys.KeyServiceImpl, *clock) {
	t.Helper()
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	c := &clock{t: time.Now().UTC()}
	ks, err := keys.NewKeyService(signingkeytest.New(), db.NoTx{}, keys.Options{
		EncryptionKey: kek, Rotation: 720 * time.Hour, PublishLead: 15 * time.Minute, MaxTokenTTL: 15 * time.Minute, Now: c.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	ts := token.NewTokenService(ks, token.Options{Issuer: issuer, AccessTTL: 15 * time.Minute, VoiceTTL: 5 * time.Minute, Now: c.Now})
	return ts, ks, c
}

var alice = &user.User{ID: "usr_01HZZZZZZZZZZZZZZZZZZZZZZZ", Username: "alice", Role: user.RoleUser}

// verifyWithJWKS checks a token the way an external service would: only
// with the published JWKS.
func verifyWithJWKS(t *testing.T, set keys.JWKS, raw, aud string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(tk *jwt.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		for _, k := range set.Keys {
			if k.Kid == kid {
				b, err := base64.RawURLEncoding.DecodeString(k.X)
				return ed25519.PublicKey(b), err
			}
		}
		return nil, jwt.ErrTokenUnverifiable
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(issuer), jwt.WithAudience(aud), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatalf("JWKS verification failed: %v", err)
	}
	return claims
}

func TestAccessTokenRoundTrip(t *testing.T) {
	ctx := context.Background()
	ts, ks, _ := setup(t)
	raw, exp, err := ts.MintAccess(ctx, alice, "ses_1", token.Grants{})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < 14*time.Minute || d > 15*time.Minute {
		t.Fatalf("exp in %v, want ~15m", d)
	}
	c, err := ts.VerifyAccess(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != alice.ID || c.SessionID != "ses_1" || c.Name != "alice" || c.Role != "user" || c.ID == "" {
		t.Fatalf("claims = %+v", c)
	}
	mc := verifyWithJWKS(t, ks.JWKS(ctx), raw, token.AudienceBoson)
	if mc["aud"] != "boson" {
		t.Fatalf("aud = %#v, want plain string", mc["aud"])
	}
	tk, _, _ := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if tk.Header["typ"] != "at+jwt" || tk.Header["alg"] != "EdDSA" || tk.Header["kid"] == "" {
		t.Fatalf("header = %v", tk.Header)
	}
	for _, claim := range []string{"iss", "sub", "aud", "sid", "name", "role", "iat", "nbf", "exp", "jti"} {
		if _, ok := mc[claim]; !ok {
			t.Errorf("missing claim %s", claim)
		}
	}
	if strings.Contains(raw, "bsr_") {
		t.Fatal("access token must not embed a refresh token")
	}
}

var (
	memberGrants = token.Grants{Perms: []string{perm.ChannelCreate, perm.VoiceCreate}}
	adminGrants  = token.Grants{Roles: []string{"Admin"}, Perms: perm.Without(perm.RolesOwner)}
)

func TestAccessTokenRoleClaims(t *testing.T) {
	ctx := context.Background()
	ts, ks, _ := setup(t)
	raw, _, err := ts.MintAccess(ctx, alice, "ses_1", adminGrants)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ts.VerifyAccess(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	// The 1.x role claim follows admin.panel, not users.role.
	if c.Role != "admin" || len(c.Roles) != 1 || c.Roles[0] != "Admin" || len(c.Perms) != len(perm.IDs())-1 {
		t.Fatalf("claims = %+v", c)
	}
	raw, _, _ = ts.MintAccess(ctx, &user.User{ID: "usr_3", Username: "mod", Role: user.RoleAdmin}, "ses_3",
		token.Grants{Roles: []string{"Moderator"}, Perms: []string{perm.UsersView}})
	mc := verifyWithJWKS(t, ks.JWKS(ctx), raw, token.AudienceBoson)
	if mc["role"] != "user" {
		t.Fatalf("role without admin.panel = %v, want user", mc["role"])
	}
	raw, _, _ = ts.MintAccess(ctx, alice, "ses_1", token.Grants{})
	mc = verifyWithJWKS(t, ks.JWKS(ctx), raw, token.AudienceBoson)
	if perms, ok := mc["perms"].([]any); !ok || len(perms) != 0 {
		t.Fatalf("perms must be present (empty) = %#v", mc["perms"])
	}
}

func TestOldKidVerifiesAfterRotation(t *testing.T) {
	ctx := context.Background()
	ts, ks, c := setup(t)
	before, _, _ := ts.MintAccess(ctx, alice, "ses_1", token.Grants{})
	oldKid, _, _ := ks.SigningKey(ctx)

	newKid, err := ks.Rotate(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	after, _, _ := ts.MintAccess(ctx, alice, "ses_1", token.Grants{})
	tk, _, _ := jwt.NewParser().ParseUnverified(after, jwt.MapClaims{})
	if tk.Header["kid"] != newKid || newKid == oldKid {
		t.Fatalf("new token signed with %v, want %s", tk.Header["kid"], newKid)
	}
	c.Add(10 * time.Minute)
	for name, raw := range map[string]string{"old kid": before, "new kid": after} {
		if _, err := ts.VerifyAccess(ctx, raw); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		verifyWithJWKS(t, ks.JWKS(ctx), raw, token.AudienceBoson)
	}
}

func TestVoiceToken(t *testing.T) {
	ctx := context.Background()
	ts, ks, _ := setup(t)
	raw, exp, err := ts.MintVoice(ctx, alice, "ses_1", []string{"lobby", "dev"}, memberGrants)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < 4*time.Minute || d > 5*time.Minute {
		t.Fatalf("voice exp in %v, want ~5m", d)
	}
	mc := verifyWithJWKS(t, ks.JWKS(ctx), raw, token.AudienceQuicvoice)
	if mc["sub"] != alice.ID || mc["name"] != "alice" || mc["role"] != "speaker" || mc["aud"] != "quicvoice" {
		t.Fatalf("voice claims = %v", mc)
	}
	rooms, _ := mc["rooms"].([]any)
	if len(rooms) != 2 || rooms[0] != "lobby" {
		t.Fatalf("rooms = %v", mc["rooms"])
	}
	if perms, _ := mc["perms"].([]any); len(perms) != 2 || perms[0] != "channel.create" || perms[1] != "voice.create" {
		t.Fatalf("voice perms = %v", mc["perms"])
	}
	if _, ok := mc["roles"]; ok {
		t.Fatal("roles must be omitted when the user has none")
	}
	admin := &user.User{ID: "usr_2", Username: "root2", Role: user.RoleAdmin}
	raw, _, _ = ts.MintVoice(ctx, admin, "ses_2", nil, adminGrants)
	mc = verifyWithJWKS(t, ks.JWKS(ctx), raw, token.AudienceQuicvoice)
	if mc["role"] != "moderator" {
		t.Fatalf("admin voice role = %v, want moderator", mc["role"])
	}
	// Voice tokens carry only the network permissions.
	if perms, _ := mc["perms"].([]any); len(perms) != 4 || fmt.Sprint(perms) != "[channel.create voice.create voice.manage_any voice.bypass_locks]" {
		t.Fatalf("admin voice perms = %v", mc["perms"])
	}
	if roles, _ := mc["roles"].([]any); len(roles) != 1 || roles[0] != "Admin" {
		t.Fatalf("voice roles = %v", mc["roles"])
	}
	if _, ok := mc["rooms"]; ok {
		t.Fatal("rooms must be omitted when empty (any room)")
	}
	// A voice token is not an access token.
	if _, err := ts.VerifyAccess(ctx, raw); err == nil {
		t.Fatal("voice token accepted as access token")
	}
}

func TestRejects(t *testing.T) {
	ctx := context.Background()
	ts, ks, c := setup(t)
	good, _, _ := ts.MintAccess(ctx, alice, "ses_1", token.Grants{})

	parts := strings.Split(good, ".")
	sig := []byte(parts[2])
	sig[3] ^= 1
	tampered := parts[0] + "." + parts[1] + "." + string(sig)

	none := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": issuer, "sub": alice.ID, "aud": "boson", "sid": "s", "exp": time.Now().Add(time.Hour).Unix()})
	none.Header["typ"] = "at+jwt"
	noneRaw, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)

	// Correct key, wrong typ (e.g. an ID token from a future OIDC phase).
	kid, priv, _ := ks.SigningKey(ctx)
	wrongTyp := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": issuer, "sub": alice.ID, "aud": "boson", "sid": "s", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	wrongTyp.Header["kid"] = kid
	wrongTypRaw, _ := wrongTyp.SignedString(priv)

	wrongIss := token.NewTokenService(ks, token.Options{Issuer: "https://evil.example", AccessTTL: time.Minute, VoiceTTL: time.Minute, Now: c.Now})
	evil, _, _ := wrongIss.MintAccess(ctx, alice, "ses_1", token.Grants{})

	for name, raw := range map[string]string{
		"tampered": tampered, "alg none": noneRaw, "wrong typ": wrongTypRaw, "wrong iss": evil, "garbage": "a.b.c", "empty": "",
	} {
		if _, err := ts.VerifyAccess(ctx, raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	c.Add(16 * time.Minute)
	if _, err := ts.VerifyAccess(ctx, good); err == nil {
		t.Error("expired token accepted")
	}
}
