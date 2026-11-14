package integration

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

// TestOIDCAgainstDex runs the full browser flow against a real Dex
// (make test-dex-up). Skipped unless TEST_DEX_ISSUER is set.
func TestOIDCAgainstDex(t *testing.T) {
	issuer := os.Getenv("TEST_DEX_ISSUER")
	if issuer == "" {
		t.Skip("TEST_DEX_ISSUER not set (make test-dex-up)")
	}
	e := newEnv(t)
	adminAT := e.adminToken("dexadmin")
	r := e.api("POST", "/v1/admin/sso/providers", map[string]any{
		"slug": "dex", "kind": "oidc", "display_name": "Dex", "enabled": true, "allow_signup": true, "trust_email": true,
		"config": map[string]any{"issuer": issuer, "client_id": "boson-auth", "client_secret": "boson-auth-secret",
			"scopes": []string{"openid", "email", "profile"}},
	}, bearer(adminAT))
	e.expect(r, 201, "")
	if r.str("provider", "redirect_uri") != "http://auth.integration.test/v1/sso/dex/callback" {
		t.Fatalf("redirect_uri: %s", r.raw)
	}
	tr := e.api("POST", "/v1/admin/sso/providers/"+r.str("provider", "id")+"/test", nil, bearer(adminAT))
	if tr.body["ok"] != true {
		t.Fatalf("test against Dex: %s", tr.raw)
	}

	login := func(query url.Values) *url.URL {
		c := e.browser()
		res, body := e.get(c, e.public.URL+"/v1/sso/dex/start?"+query.Encode())
		next := location(t, res, body)
		// Follow Dex's redirects, filling in its login form on the way.
		for hop := 0; hop < 10 && strings.HasPrefix(next.String(), issuer); hop++ {
			res, body = e.get(c, next.String())
			if res.StatusCode == 200 && strings.Contains(body, `name="password"`) {
				action, form := parseForm(t, body)
				au, _ := next.Parse(action)
				form.Set("login", "dex.user@example.com")
				form.Set("password", "dex-password")
				res, body = e.postForm(c, au.String(), form)
			}
			next = res.Request.URL.ResolveReference(location(t, res, body))
		}
		if !strings.HasPrefix(next.String(), e.cfg.HTTPConfig.PublicURL+"/v1/sso/dex/callback?") {
			t.Fatalf("Dex did not return to our callback: %s", next)
		}
		res, body = e.get(c, e.local(next.String()))
		return location(t, res, body)
	}

	// Cookie mode.
	loc := login(url.Values{"return_to": {"/welcome"}})
	if loc.String() != "https://app.integration.test/welcome" {
		t.Fatalf("after Dex login: %s", loc)
	}
	// Code mode with PKCE, like the desktop client.
	verifier := strings.Repeat("d", 64)
	loc = login(url.Values{"return_to": {"http://127.0.0.1:47000/cb"}, "code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"}})
	x := e.api("POST", "/v1/sso/exchange", map[string]string{"code": loc.Query().Get("code"), "code_verifier": verifier})
	e.expect(x, 200, "")
	u := x.body["user"].(map[string]any)
	if u["email"] != "dex.user@example.com" || u["email_verified"] != true {
		t.Fatalf("Dex user: %s", x.raw)
	}
	ids := e.api("GET", "/v1/me/identities", nil, bearer(x.str("access_token"))).list("identities")
	if len(ids) != 1 || ids[0]["provider_slug"] != "dex" || ids[0]["subject"] == "" {
		t.Fatalf("identities: %v", ids)
	}
	t.Logf("Dex sign-in OK: user %s (%s), subject %s", u["username"], u["id"], ids[0]["subject"])
}
