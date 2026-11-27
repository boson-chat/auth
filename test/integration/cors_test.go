package integration

import (
	"testing"

	"github.com/boson-chat/auth/config"
)

// A Boson web client on another install's origin uses the token API.
func TestCORSAnyOriginTokenAPI(t *testing.T) {
	e := newEnv(t)
	e.registerVerified("nora", "nora@example.com")
	origin := header("Origin", "https://chat.other.example")
	preflight := func(path, method string) resp {
		return e.api("OPTIONS", path, nil, origin, header("Access-Control-Request-Method", method),
			header("Access-Control-Request-Headers", "authorization, content-type"))
	}
	for _, c := range []struct{ path, method string }{
		{"/v1/config", "GET"}, {"/v1/login", "POST"}, {"/v1/register", "POST"}, {"/v1/token/refresh", "POST"},
		{"/v1/logout", "POST"}, {"/v1/me", "PATCH"}, {"/v1/voice/token", "POST"}, {"/v1/sso/exchange", "POST"},
		{"/v1/me/identities/x", "DELETE"}, {"/v1/federation/login", "POST"},
	} {
		r := preflight(c.path, c.method)
		if r.status != 204 || r.header.Get("Access-Control-Allow-Origin") != "*" || r.header.Get("Access-Control-Allow-Credentials") != "" ||
			r.header.Get("Access-Control-Allow-Headers") == "" || r.header.Get("Access-Control-Max-Age") == "" {
			t.Fatalf("preflight %s %s: %d %v", c.method, c.path, r.status, r.header)
		}
	}

	cfg := e.api("GET", "/v1/config", nil, origin)
	e.expect(cfg, 200, "")
	if cfg.header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("config: %v", cfg.header)
	}
	login := e.api("POST", "/v1/login", map[string]string{"login": "nora", "password": pw}, origin)
	e.expect(login, 200, "")
	tok := login.str("access_token")
	if tok == "" || login.header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("login: %s %v", login.raw, login.header)
	}
	me := e.api("GET", "/v1/me", nil, origin, bearer(tok))
	e.expect(me, 200, "")
	if me.header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("me: %v", me.header)
	}
	ref := e.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": login.str("refresh_token")}, origin)
	e.expect(ref, 200, "")
	e.expect(e.api("POST", "/v1/logout", map[string]string{"refresh_token": ref.str("refresh_token")}, origin, bearer(ref.str("access_token"))), 204, "")

	// Admin and SSO stay closed to foreign origins.
	if r := e.api("GET", "/v1/admin/users", nil, origin, bearer(tok)); r.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("admin opened: %v", r.header)
	}
	for _, p := range []string{"/v1/admin/users", "/v1/sso/x/start", "/v1/sso/x/callback", "/v1/email/verify", "/v1/password/reset"} {
		if r := preflight(p, "POST"); r.status == 204 || r.header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("%s opened: %d %v", p, r.status, r.header)
		}
	}
}

func TestCORSAnyOriginOff(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.HTTPConfig.CORSAnyOrigin = false })
	origin := header("Origin", "https://chat.other.example")
	if r := e.api("GET", "/v1/config", nil, origin); r.status != 200 || r.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("config: %d %v", r.status, r.header)
	}
	if r := e.api("OPTIONS", "/v1/login", nil, origin, header("Access-Control-Request-Method", "POST")); r.status == 204 ||
		r.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("login preflight: %d %v", r.status, r.header)
	}
	// The allowlist still works, with credentials.
	app := header("Origin", "https://app.integration.test")
	if r := e.api("GET", "/v1/config", nil, app); r.header.Get("Access-Control-Allow-Origin") != "https://app.integration.test" ||
		r.header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("allowlist: %v", r.header)
	}
	// Federation is always open.
	if r := e.api("OPTIONS", "/v1/federation/login", nil, origin, header("Access-Control-Request-Method", "POST")); r.status != 204 ||
		r.header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("federation: %d %v", r.status, r.header)
	}
}
