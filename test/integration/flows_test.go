package integration

import (
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/services/account"
	"github.com/golang-jwt/jwt/v5"
)

func TestRegisterVerifyLoginRefreshReuseLogout(t *testing.T) {
	e := newEnv(t)

	r := e.api("POST", "/v1/register", map[string]string{"username": "Alice", "email": "alice@example.com", "password": pw})
	e.expect(r, 201, "")
	if r.body["user"].(map[string]any)["email_verified"] != false {
		t.Fatal("new user must start unverified")
	}
	msg := e.mail.next(t)
	if msg.To != "alice@example.com" || !strings.HasPrefix(msg.Link, "https://app.integration.test/verify-email#token=") {
		t.Fatalf("verification email: to=%s link=%s", msg.To, msg.Link)
	}
	if !strings.Contains(msg.Text, msg.Link) || !strings.Contains(msg.HTML, "Verify email") {
		t.Fatal("email body missing link")
	}

	// Unverified: correct password is still refused.
	e.expect(e.login("alice", pw), 403, "email_not_verified")

	verifyTok := tokenFromLink(t, msg.Link)
	e.expect(e.api("POST", "/v1/email/verify", map[string]string{"token": verifyTok}), 200, "")
	e.expect(e.api("POST", "/v1/email/verify", map[string]string{"token": verifyTok}), 400, "invalid_token") // single use

	// Login by case-variant username and by email.
	r = e.login("ALICE", pw)
	e.expect(r, 200, "")
	access, refresh := r.str("access_token"), r.str("refresh_token")
	if access == "" || !strings.HasPrefix(refresh, "bsr_") || r.body["expires_in"].(float64) < 800 {
		t.Fatalf("login response: %s", r.raw)
	}
	e.expect(e.login("Alice@Example.com", pw), 200, "")

	me := e.api("GET", "/v1/me", nil, bearer(access))
	e.expect(me, 200, "")
	if me.str("user", "username") != "Alice" || me.str("user", "role") != "user" || me.body["user"].(map[string]any)["email_verified"] != true {
		t.Fatalf("me: %s", me.raw)
	}
	e.expect(e.api("PATCH", "/v1/me", map[string]string{"display_name": "Alice A."}, bearer(access)), 200, "")
	if got := e.api("GET", "/v1/me", nil, bearer(access)).str("user", "display_name"); got != "Alice A." {
		t.Fatalf("display_name = %q", got)
	}

	// Refresh rotates.
	r = e.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": refresh})
	e.expect(r, 200, "")
	access2, refresh2 := r.str("access_token"), r.str("refresh_token")
	if refresh2 == refresh || access2 == "" {
		t.Fatal("refresh did not rotate")
	}
	e.expect(e.api("GET", "/v1/me", nil, bearer(access2)), 200, "")

	// Reusing the old refresh token kills the family and the session.
	e.expect(e.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": refresh}), 401, "invalid_refresh_token")
	e.expect(e.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": refresh2}), 401, "invalid_refresh_token")
	e.expect(e.api("GET", "/v1/me", nil, bearer(access2)), 401, "unauthenticated")

	// Fresh login, list sessions, logout.
	r = e.login("alice", pw)
	access3, refresh3 := r.str("access_token"), r.str("refresh_token")
	sessions := e.api("GET", "/v1/sessions", nil, bearer(access3))
	e.expect(sessions, 200, "")
	list := sessions.body["sessions"].([]any)
	if len(list) != 2 { // the email login above + this one
		t.Fatalf("active sessions = %d, want 2: %s", len(list), sessions.raw)
	}
	e.expect(e.api("POST", "/v1/logout", nil, bearer(access3)), 204, "")
	e.expect(e.api("GET", "/v1/me", nil, bearer(access3)), 401, "")
	e.expect(e.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": refresh3}), 401, "invalid_refresh_token")
}

func TestRevokeOtherSession(t *testing.T) {
	e := newEnv(t)
	e.registerVerified("bob", "bob@example.com")
	a := e.login("bob", pw)
	b := e.login("bob", pw)
	e.expect(e.api("DELETE", "/v1/sessions/"+b.str("session_id"), nil, bearer(a.str("access_token"))), 204, "")
	e.expect(e.api("GET", "/v1/me", nil, bearer(b.str("access_token"))), 401, "")
	e.expect(e.api("GET", "/v1/me", nil, bearer(a.str("access_token"))), 200, "")

	// Someone else's session id looks like a missing one.
	e.registerVerified("carol", "carol@example.com")
	c := e.login("carol", pw)
	e.expect(e.api("DELETE", "/v1/sessions/"+a.str("session_id"), nil, bearer(c.str("access_token"))), 404, "not_found")
	e.expect(e.api("GET", "/v1/me", nil, bearer(a.str("access_token"))), 200, "")
}

func TestForgotResetNoEnumerationRevokesSessions(t *testing.T) {
	e := newEnv(t)
	e.registerVerified("dave", "dave@example.com")
	s1 := e.login("dave", pw)
	s2 := e.login("dave", pw)

	unknown := e.api("POST", "/v1/password/forgot", map[string]string{"email": "nobody@example.com"})
	known := e.api("POST", "/v1/password/forgot", map[string]string{"email": "DAVE@example.com"})
	e.expect(unknown, 202, "")
	e.expect(known, 202, "")
	if string(unknown.raw) != string(known.raw) {
		t.Fatalf("responses differ: %s vs %s", unknown.raw, known.raw)
	}
	msg := e.mail.next(t)
	if msg.To != "dave@example.com" { // the stored address, not the request's casing
		t.Fatalf("reset sent to %q", msg.To)
	}
	if !strings.HasPrefix(msg.Link, "https://app.integration.test/reset-password#token=") {
		t.Fatalf("reset link %s", msg.Link)
	}
	e.mail.none(t, 200*time.Millisecond) // nothing for the unknown address

	tok := tokenFromLink(t, msg.Link)
	// Policy failure does not burn the token.
	e.expect(e.api("POST", "/v1/password/reset", map[string]string{"token": tok, "new_password": "short"}), 400, "weak_password")
	e.expect(e.api("POST", "/v1/password/reset", map[string]string{"token": tok, "new_password": "dave"}), 400, "weak_password")
	e.expect(e.api("POST", "/v1/password/reset", map[string]string{"token": tok, "new_password": "a brand new passphrase"}), 200, "")
	e.expect(e.api("POST", "/v1/password/reset", map[string]string{"token": tok, "new_password": "another new passphrase"}), 400, "invalid_token")

	for _, s := range []resp{s1, s2} {
		e.expect(e.api("GET", "/v1/me", nil, bearer(s.str("access_token"))), 401, "")
		e.expect(e.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": s.str("refresh_token")}), 401, "")
	}
	e.expect(e.login("dave", pw), 401, "invalid_credentials")
	e.expect(e.login("dave", "a brand new passphrase"), 200, "")

	// A second forgot invalidates the previous link.
	e.api("POST", "/v1/password/forgot", map[string]string{"email": "dave@example.com"})
	first := tokenFromLink(t, e.mail.next(t).Link)
	e.api("POST", "/v1/password/forgot", map[string]string{"email": "dave@example.com"})
	second := tokenFromLink(t, e.mail.next(t).Link)
	e.expect(e.api("POST", "/v1/password/reset", map[string]string{"token": first, "new_password": "yet another passphrase"}), 400, "invalid_token")
	e.expect(e.api("POST", "/v1/password/reset", map[string]string{"token": second, "new_password": "yet another passphrase"}), 200, "")
}

func TestChangePasswordKeepsCurrentSession(t *testing.T) {
	e := newEnv(t)
	e.registerVerified("erin", "erin@example.com")
	cur := e.login("erin", pw)
	other := e.login("erin", pw)
	at := cur.str("access_token")
	e.expect(e.api("POST", "/v1/password/change", map[string]string{"current": "wrong password!", "new": "new passphrase ok"}, bearer(at)), 403, "invalid_password")
	e.expect(e.api("POST", "/v1/password/change", map[string]string{"current": pw, "new": "new passphrase ok"}, bearer(at)), 200, "")
	e.expect(e.api("GET", "/v1/me", nil, bearer(at)), 200, "")
	e.expect(e.api("GET", "/v1/me", nil, bearer(other.str("access_token"))), 401, "")
	e.expect(e.login("erin", "new passphrase ok"), 200, "")
}

func TestLoginFailuresLookAlike(t *testing.T) {
	e := newEnv(t)
	e.registerVerified("frank", "frank@example.com")
	a := e.login("frank", "not the password")
	b := e.login("nosuchuser", "not the password")
	c := e.login("nobody@example.com", "not the password")
	for _, r := range []resp{a, b, c} {
		e.expect(r, 401, "invalid_credentials")
	}
	if string(a.raw) != string(b.raw) || string(b.raw) != string(c.raw) {
		t.Fatal("login failure bodies differ")
	}
}

func TestVoiceTokenVerifiesAgainstJWKS(t *testing.T) {
	e := newEnv(t)
	uid := e.registerVerified("gina", "gina@example.com")
	at := e.login("gina", pw).str("access_token")

	disc := e.api("GET", "/.well-known/openid-configuration", nil)
	e.expect(disc, 200, "")
	if disc.str("issuer") != issuer || disc.str("jwks_uri") != "http://auth.integration.test/.well-known/jwks.json" {
		t.Fatalf("discovery: %s", disc.raw)
	}
	jwks := e.api("GET", "/.well-known/jwks.json", nil)
	if cc := jwks.header.Get("Cache-Control"); cc != "public, max-age=300" {
		t.Fatalf("JWKS Cache-Control = %q", cc)
	}

	r := e.api("POST", "/v1/voice/token", map[string]any{"rooms": []string{"lobby"}}, bearer(at))
	e.expect(r, 200, "")
	keyfunc := e.jwksKeyfunc()
	claims := jwt.MapClaims{}
	tk, err := jwt.ParseWithClaims(r.str("token"), claims, keyfunc,
		jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(issuer), jwt.WithAudience("quicvoice"), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatalf("voice token does not verify against JWKS: %v", err)
	}
	if claims["sub"] != uid || claims["name"] != "gina" || claims["role"] != "speaker" || claims["aud"] != "quicvoice" {
		t.Fatalf("voice claims %v", claims)
	}
	if rooms := claims["rooms"].([]any); len(rooms) != 1 || rooms[0] != "lobby" {
		t.Fatalf("rooms %v", claims["rooms"])
	}
	exp, _ := claims.GetExpirationTime()
	if d := time.Until(exp.Time); d <= 4*time.Minute || d > 5*time.Minute {
		t.Fatalf("voice exp in %v", d)
	}
	if tk.Header["kid"] == "" {
		t.Fatal("missing kid")
	}

	// Access tokens verify the same way with aud=boson; a voice token can't
	// authenticate API calls.
	if _, err := jwt.Parse(at, keyfunc, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(issuer), jwt.WithAudience("boson")); err != nil {
		t.Fatalf("access token vs JWKS: %v", err)
	}
	e.expect(e.api("GET", "/v1/me", nil, bearer(r.str("token"))), 401, "")

	// Admins get moderator.
	if _, err := e.app.Account.CreateUser(t.Context(), "", account.CreateUserInput{Username: "boss", Email: "boss@example.com", Password: pw, Role: "admin", EmailVerified: true}); err != nil {
		t.Fatal(err)
	}
	r = e.api("POST", "/v1/voice/token", nil, bearer(e.login("boss", pw).str("access_token")))
	claims = jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(r.str("token"), claims, keyfunc, jwt.WithAudience("quicvoice")); err != nil || claims["role"] != "moderator" {
		t.Fatalf("admin voice role %v (%v)", claims["role"], err)
	}
	e.expect(e.api("POST", "/v1/voice/token", nil), 401, "")
}

func TestKeyRotationKeepsOldTokensValid(t *testing.T) {
	e := newEnv(t)
	e.registerVerified("hank", "hank@example.com")
	at := e.login("hank", pw).str("access_token")
	if _, err := e.app.Keys.Rotate(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	e.expect(e.api("GET", "/v1/me", nil, bearer(at)), 200, "")
	at2 := e.login("hank", pw).str("access_token")
	old, _, _ := jwt.NewParser().ParseUnverified(at, jwt.MapClaims{})
	cur, _, _ := jwt.NewParser().ParseUnverified(at2, jwt.MapClaims{})
	if old.Header["kid"] == cur.Header["kid"] {
		t.Fatal("rotation did not change the signing kid")
	}
	keyfunc := e.jwksKeyfunc()
	for _, tok := range []string{at, at2} {
		if _, err := jwt.Parse(tok, keyfunc, jwt.WithAudience("boson")); err != nil {
			t.Fatalf("JWKS must hold both kids: %v", err)
		}
	}
}

func TestDisabledUserCannotLoginOrRefresh(t *testing.T) {
	e := newEnv(t)
	if _, err := e.app.Account.CreateUser(t.Context(), "", account.CreateUserInput{Username: "admin1", Email: "admin1@example.com", Password: pw, Role: "admin", EmailVerified: true}); err != nil {
		t.Fatal(err)
	}
	adminAT := e.login("admin1", pw).str("access_token")
	uid := e.registerVerified("ivan", "ivan@example.com")
	s := e.login("ivan", pw)

	// Non-admins can't use the admin API.
	e.expect(e.api("GET", "/v1/admin/users", nil, bearer(s.str("access_token"))), 403, "forbidden")

	users := e.api("GET", "/v1/admin/users?q=iva", nil, bearer(adminAT))
	e.expect(users, 200, "")
	if users.body["total"].(float64) != 1 {
		t.Fatalf("admin search: %s", users.raw)
	}
	e.expect(e.api("POST", "/v1/admin/users/"+uid+"/disable", nil, bearer(adminAT)), 200, "")

	e.expect(e.api("GET", "/v1/me", nil, bearer(s.str("access_token"))), 401, "")
	e.expect(e.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": s.str("refresh_token")}), 401, "")
	e.expect(e.login("ivan", pw), 403, "account_disabled")
	e.expect(e.login("ivan", "wrong password!"), 401, "invalid_credentials") // no hint without the password

	iv := e.do(e.internal, "POST", "/internal/v1/verify-password", map[string]string{"username": "ivan", "password": pw},
		header("X-Internal-Token", e.cfg.InternalConfig.APIToken))
	e.expect(iv, 200, "")
	if iv.body["ok"] != false || iv.str("reason") != "account_disabled" {
		t.Fatalf("internal verify for disabled user: %s", iv.raw)
	}

	// Re-enable: login works again; old sessions stay dead.
	e.expect(e.api("POST", "/v1/admin/users/"+uid+"/enable", nil, bearer(adminAT)), 200, "")
	e.expect(e.login("ivan", pw), 200, "")
	e.expect(e.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": s.str("refresh_token")}), 401, "")

	audit := e.api("GET", "/v1/admin/audit?limit=100", nil, bearer(adminAT))
	if !strings.Contains(string(audit.raw), "admin_user_disabled") {
		t.Fatalf("disable not audited: %s", audit.raw)
	}
}

func TestAdminSessions(t *testing.T) {
	e := newEnv(t)
	if _, err := e.app.Account.CreateUser(t.Context(), "", account.CreateUserInput{Username: "admin2", Email: "a2@example.com", Password: pw, Role: "admin", EmailVerified: true}); err != nil {
		t.Fatal(err)
	}
	adminAT := e.login("admin2", pw).str("access_token")
	uid := e.registerVerified("judy", "judy@example.com")
	s := e.login("judy", pw)
	list := e.api("GET", "/v1/admin/users/"+uid+"/sessions", nil, bearer(adminAT))
	e.expect(list, 200, "")
	ss := list.body["sessions"].([]any)
	if len(ss) != 1 {
		t.Fatalf("sessions: %s", list.raw)
	}
	sid := ss[0].(map[string]any)["id"].(string)
	e.expect(e.api("DELETE", "/v1/admin/sessions/"+sid, nil, bearer(adminAT)), 204, "")
	e.expect(e.api("GET", "/v1/me", nil, bearer(s.str("access_token"))), 401, "")
	e.expect(e.api("DELETE", "/v1/admin/sessions/ses_nope", nil, bearer(adminAT)), 404, "")
}

func TestCookieModeAndCSRF(t *testing.T) {
	e := newEnv(t)
	e.registerVerified("kim", "kim@example.com")
	xrw := header("X-Requested-With", "fetch")

	e.expect(e.api("POST", "/v1/login", map[string]any{"login": "kim", "password": pw, "cookie": true}), 403, "csrf")
	r := e.api("POST", "/v1/login", map[string]any{"login": "kim", "password": pw, "cookie": true}, xrw)
	e.expect(r, 200, "")
	if r.str("access_token") != "" || r.str("refresh_token") != "" {
		t.Fatal("cookie mode must not return tokens in the body")
	}
	var at, rt string
	for _, c := range r.header.Values("Set-Cookie") {
		if !strings.Contains(c, "HttpOnly") || !strings.Contains(c, "SameSite=Lax") {
			t.Fatalf("cookie flags: %s", c)
		}
		if strings.HasPrefix(c, "boson_at=") {
			at = c
		}
		if strings.HasPrefix(c, "boson_rt=") {
			rt = c
		}
	}
	if at == "" || rt == "" || !strings.Contains(rt, "Path=/v1") {
		t.Fatalf("cookies: %v", r.header.Values("Set-Cookie"))
	}

	// Cookie auth: safe methods fine, unsafe ones need the header.
	e.expect(e.api("GET", "/v1/me", nil), 200, "")
	e.expect(e.api("PATCH", "/v1/me", map[string]string{"display_name": "K"}), 403, "csrf")
	e.expect(e.api("PATCH", "/v1/me", map[string]string{"display_name": "K"}, xrw), 200, "")
	e.expect(e.api("POST", "/v1/token/refresh", nil), 403, "csrf")
	r = e.api("POST", "/v1/token/refresh", nil, xrw)
	e.expect(r, 200, "")
	if r.str("refresh_token") != "" || len(r.header.Values("Set-Cookie")) != 2 {
		t.Fatalf("cookie refresh: %s %v", r.raw, r.header.Values("Set-Cookie"))
	}
	e.expect(e.api("POST", "/v1/logout", nil), 403, "csrf")
	e.expect(e.api("POST", "/v1/logout", nil, xrw), 204, "")
	e.expect(e.api("GET", "/v1/me", nil), 401, "")

	// Forms can't post: JSON content type is required.
	r = e.api("POST", "/v1/login", nil, header("Content-Type", "application/x-www-form-urlencoded"))
	e.expect(r, 415, "unsupported_media_type")

	// CORS: only the configured origin is reflected.
	pre := e.api("OPTIONS", "/v1/login", nil, header("Origin", "https://app.integration.test"), header("Access-Control-Request-Method", "POST"))
	if pre.status != 204 || pre.header.Get("Access-Control-Allow-Origin") != "https://app.integration.test" || pre.header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("preflight: %d %v", pre.status, pre.header)
	}
	evil := e.api("OPTIONS", "/v1/login", nil, header("Origin", "https://evil.example"), header("Access-Control-Request-Method", "POST"))
	if evil.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("foreign origin allowed")
	}
}

func TestInternalVerifyPassword(t *testing.T) {
	e := newEnv(t)
	uid := e.registerVerified("lena", "lena@example.com")
	body := map[string]string{"username": "LENA", "password": pw}
	e.expect(e.do(e.internal, "POST", "/internal/v1/verify-password", body), 401, "")
	e.expect(e.do(e.internal, "POST", "/internal/v1/verify-password", body, header("X-Internal-Token", "nope")), 401, "")
	tok := header("X-Internal-Token", e.cfg.InternalConfig.APIToken)
	r := e.do(e.internal, "POST", "/internal/v1/verify-password", body, tok)
	e.expect(r, 200, "")
	if r.body["ok"] != true || r.str("user_id") != uid || r.str("username") != "lena" {
		t.Fatalf("verify: %s", r.raw)
	}
	r = e.do(e.internal, "POST", "/internal/v1/verify-password", map[string]string{"username": "lena", "password": "wrong password!"}, tok)
	if r.body["ok"] != false || r.str("reason") != "invalid_credentials" {
		t.Fatalf("wrong pw: %s", r.raw)
	}
	// Not on the public listener.
	e.expect(e.api("POST", "/internal/v1/verify-password", body, tok), 404, "")
	// Health and metrics on the internal listener.
	e.expect(e.do(e.internal, "GET", "/healthz", nil), 200, "")
	e.expect(e.api("GET", "/healthz", nil), 200, "")
	e.expect(e.api("GET", "/readyz", nil), 200, "")
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.RateLimitConfig = config.RateLimitConfig{Enabled: true, IPBurst: 100, IPPerMinute: 1, AccountBurst: 3, AccountPerMinute: 1}
	})
	for i := range 3 {
		e.expect(e.login("mallory", "guess number "+strconv.Itoa(i)), 401, "")
	}
	r := e.login("MALLORY", "guess number 4") // same account bucket regardless of case
	e.expect(r, 429, "rate_limited")
	ra, err := strconv.Atoi(r.header.Get("Retry-After"))
	if err != nil || ra < 1 || ra > 60 {
		t.Fatalf("Retry-After = %q", r.header.Get("Retry-After"))
	}
	// Another account from the same IP is unaffected.
	e.expect(e.login("someoneelse", "guess number 1"), 401, "")
}

func TestRegistrationModesAndValidation(t *testing.T) {
	t.Run("closed", func(t *testing.T) {
		e := newEnv(t, func(c *config.Config) { c.AccountConfig.Registration = config.RegistrationClosed })
		e.expect(e.api("POST", "/v1/register", map[string]string{"username": "nina", "email": "n@example.com", "password": pw}), 403, "registration_closed")
	})
	t.Run("invite", func(t *testing.T) {
		e := newEnv(t, func(c *config.Config) { c.AccountConfig.Registration = config.RegistrationInvite })
		e.expect(e.api("POST", "/v1/register", map[string]string{"username": "oscar", "email": "o@example.com", "password": pw}), 403, "invite_required")
		code, _, err := e.app.Admin.CreateInvite(t.Context(), "", 1, time.Hour, "test")
		if err != nil {
			t.Fatal(err)
		}
		e.expect(e.api("POST", "/v1/register", map[string]string{"username": "oscar", "email": "o@example.com", "password": pw, "invite_code": "inv_wrong"}), 403, "invite_required")
		e.expect(e.api("POST", "/v1/register", map[string]string{"username": "oscar", "email": "o@example.com", "password": pw, "invite_code": code}), 201, "")
		e.expect(e.api("POST", "/v1/register", map[string]string{"username": "oscar2", "email": "o2@example.com", "password": pw, "invite_code": code}), 403, "invite_required")
	})
	t.Run("no verification required", func(t *testing.T) {
		e := newEnv(t, func(c *config.Config) { c.AccountConfig.RequireEmailVerification = false })
		e.expect(e.api("POST", "/v1/register", map[string]string{"username": "pat", "email": "pat@example.com", "password": pw}), 201, "")
		e.expect(e.login("pat", pw), 200, "")
	})
	t.Run("validation and collisions", func(t *testing.T) {
		e := newEnv(t)
		reg := func(u, em, p string) resp {
			return e.api("POST", "/v1/register", map[string]string{"username": u, "email": em, "password": p})
		}
		e.expect(reg("1bad", "x@example.com", pw), 400, "invalid_username")
		e.expect(reg("has space", "x@example.com", pw), 400, "invalid_username")
		e.expect(reg("NickServ", "x@example.com", pw), 400, "invalid_username")
		e.expect(reg(strings.Repeat("a", 31), "x@example.com", pw), 400, "invalid_username")
		e.expect(reg("quinn", "not-an-email", pw), 400, "invalid_request")
		e.expect(reg("quinn", "q@example.com", "short"), 400, "weak_password")
		e.expect(reg("quinnquinn", "q@example.com", "QUINNQUINN"), 400, "weak_password")
		e.expect(reg("[Bot]", "bot@example.com", pw), 201, "")
		e.expect(reg("{bot}", "bot2@example.com", pw), 409, "username_taken") // RFC 1459 fold collision
		e.expect(reg("BOT2", "BOT@example.com", pw), 409, "email_taken")
		e.mail.next(t)
	})
}

func TestResendVerification(t *testing.T) {
	e := newEnv(t)
	e.expect(e.api("POST", "/v1/register", map[string]string{"username": "rita", "email": "rita@example.com", "password": pw}), 201, "")
	first := tokenFromLink(t, e.mail.next(t).Link)
	unknown := e.api("POST", "/v1/email/resend", map[string]string{"email": "ghost@example.com"})
	known := e.api("POST", "/v1/email/resend", map[string]string{"email": "rita@example.com"})
	e.expect(known, 202, "")
	if string(unknown.raw) != string(known.raw) || unknown.status != known.status {
		t.Fatal("resend leaks account existence")
	}
	second := tokenFromLink(t, e.mail.next(t).Link)
	e.expect(e.api("POST", "/v1/email/verify", map[string]string{"token": second}), 200, "")
	e.expect(e.api("POST", "/v1/email/verify", map[string]string{"token": first}), 400, "invalid_token") // siblings consumed
	e.api("POST", "/v1/email/resend", map[string]string{"email": "rita@example.com"})
	e.mail.none(t, 200*time.Millisecond) // already verified
}

func TestBuiltinPages(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/verify-email", "/reset-password", "/assets/pages.js", "/assets/pages.css"} {
		r := e.api("GET", p, nil)
		if r.status != 200 || !strings.Contains(r.header.Get("Content-Security-Policy"), "script-src 'self'") {
			t.Fatalf("%s: %d %v", p, r.status, r.header)
		}
	}
}

// Postgres text rejects invalid UTF-8 and NUL; hostile input must not 500.
func TestHostileBytes(t *testing.T) {
	e := newEnv(t)
	e.registerVerified("tess", "tess@example.com")
	r := e.api("POST", "/v1/login", map[string]any{"login": "tess", "password": pw}, header("User-Agent", "evil\xff\xfe"+strings.Repeat("é", 400)))
	e.expect(r, 200, "")
	e.expect(e.login("te\x00ss", pw), 401, "invalid_credentials")
	e.expect(e.login("\xff@example.com", pw), 401, "invalid_credentials")
	e.expect(e.api("POST", "/v1/password/forgot", map[string]string{"email": "a\x00@example.com"}), 400, "")
	e.expect(e.api("DELETE", "/v1/sessions/%FF", nil, bearer(r.str("access_token"))), 404, "")
	list := e.api("GET", "/v1/sessions", nil, bearer(r.str("access_token")))
	e.expect(list, 200, "")
	ua := list.body["sessions"].([]any)[0].(map[string]any)["user_agent"].(string)
	// One U+FFFD per run of invalid bytes, then the é's, cut on a rune boundary.
	if !strings.HasPrefix(ua, "evil�é") || len(ua) > 512 || !utf8.ValidString(ua) {
		t.Fatalf("stored user agent %q (len %d)", ua, len(ua))
	}
}
