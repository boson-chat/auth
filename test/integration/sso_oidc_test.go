package integration

import (
	"net/url"
	"strings"
	"testing"

	"github.com/boson-chat/auth/config"
	"github.com/oauth2-proxy/mockoidc"
)

func TestOIDCSignupCookieModeThenReturningLogin(t *testing.T) {
	e := newEnv(t)
	adminAT := e.adminToken("ssoadmin")
	m := mockIdP(t)
	e.oidcProvider(adminAT, "mock", m, map[string]any{"trust_email": true})

	// Listed for login buttons.
	cfg := e.api("GET", "/v1/config", nil)
	ps := cfg.list("sso_providers")
	if len(ps) != 1 || ps[0]["slug"] != "mock" || ps[0]["kind"] != "oidc" || ps[0]["display_name"] != "Mock mock" ||
		ps[0]["start_url"] != e.cfg.HTTPConfig.PublicURL+"/v1/sso/mock/start" {
		t.Fatalf("sso_providers: %s", cfg.raw)
	}

	alice := &mockoidc.MockUser{Subject: "sub-alice", Email: "Alice.Smith@corp.example", EmailVerified: true, PreferredUsername: "alice.smith"}
	res := e.oidcLogin("mock", m, alice, url.Values{"return_to": {"/home?tab=1"}})
	if res.StatusCode != 303 || res.Header.Get("Location") != "https://app.integration.test/home?tab=1" {
		t.Fatalf("callback: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	var at string
	for _, c := range res.Cookies() {
		switch c.Name {
		case "boson_at":
			at = c.Value
			if !c.HttpOnly || c.Path != "/" {
				t.Fatalf("access cookie flags: %+v", c)
			}
		case "boson_sso":
			if c.MaxAge >= 0 {
				t.Fatal("state cookie must be cleared after the callback")
			}
		}
	}
	if at == "" {
		t.Fatalf("no session cookies: %v", res.Header.Values("Set-Cookie"))
	}
	me := e.api("GET", "/v1/me", nil, bearer(at))
	e.expect(me, 200, "")
	u := me.body["user"].(map[string]any)
	if u["username"] != "alice_smith" || u["email"] != "Alice.Smith@corp.example" || u["email_verified"] != true {
		t.Fatalf("created user: %s", me.raw)
	}
	uid := u["id"].(string)
	sessions := e.api("GET", "/v1/sessions", nil, bearer(at)).list("sessions")
	if len(sessions) != 1 || sessions[0]["auth_method"] != "oidc:mock" {
		t.Fatalf("sessions: %v", sessions)
	}
	if si := e.adminUser(adminAT, uid); si["last_sign_in_method"] != "oidc:mock" || si["last_sign_in_at"] == nil || si["last_active_at"] == nil {
		t.Fatalf("SSO cookie sign-in not recorded: %v", si)
	}

	// Same subject again (even with changed claims) → same account.
	alice2 := &mockoidc.MockUser{Subject: "sub-alice", Email: "new@corp.example", EmailVerified: true, PreferredUsername: "someone-else"}
	res = e.oidcLogin("mock", m, alice2, url.Values{})
	if res.StatusCode != 303 || res.Header.Get("Location") != "https://app.integration.test/" {
		t.Fatalf("second login: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	ids := e.api("GET", "/v1/me/identities", nil, bearer(at))
	e.expect(ids, 200, "")
	list := ids.list("identities")
	if len(list) != 1 || list[0]["provider_slug"] != "mock" || list[0]["subject"] != "sub-alice" ||
		list[0]["email"] != "new@corp.example" || list[0]["last_login_at"] == nil || ids.body["has_password"] != false {
		t.Fatalf("identities: %s", ids.raw)
	}
	users := e.api("GET", "/v1/admin/users?q=alice", nil, bearer(adminAT))
	if users.body["total"].(float64) != 1 {
		t.Fatalf("returning login created another user: %s", users.raw)
	}

	// The admin sees the identity on the user.
	r := e.api("GET", "/v1/admin/users/"+uid, nil, bearer(adminAT))
	e.expect(r, 200, "")
	if li := r.list("identities"); len(li) != 1 || li[0]["provider_slug"] != "mock" || li[0]["subject"] != "sub-alice" || r.body["has_password"] != false {
		t.Fatalf("admin user: %s", r.raw)
	}
	// It is the only way in: can't unlink.
	e.expect(e.api("DELETE", "/v1/me/identities/"+list[0]["id"].(string), nil, bearer(at)), 409, "last_login_method")

	// Audit: register via oidc, two logins.
	a := e.api("GET", "/v1/admin/audit?actor="+uid+"&event=register,login", nil, bearer(adminAT))
	es := a.list("entries")
	if len(es) != 3 || es[2]["event"] != "register" || es[2]["meta"].(map[string]any)["method"] != "oidc:mock" ||
		es[0]["meta"].(map[string]any)["method"] != "oidc:mock" {
		t.Fatalf("audit: %s", a.raw)
	}
}

func TestOIDCCodeModeForDesktopClients(t *testing.T) {
	e := newEnv(t)
	adminAT := e.adminToken("ssoadmin")
	m := mockIdP(t)
	e.oidcProvider(adminAT, "corp", m, nil)

	verifier := strings.Repeat("v", 50)
	user := &mockoidc.MockUser{Subject: "desk-1", Email: "desk@corp.example", PreferredUsername: "desk"}
	q := url.Values{"return_to": {"http://127.0.0.1:53682/callback?x=1"}, "code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"}}
	res := e.oidcLogin("corp", m, user, q)
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 303 || loc.Host != "127.0.0.1:53682" || loc.Path != "/callback" || loc.Query().Get("x") != "1" {
		t.Fatalf("code redirect: %d %s", res.StatusCode, loc)
	}
	for _, c := range res.Cookies() {
		if c.Name == "boson_at" || c.Name == "boson_rt" {
			t.Fatal("code mode must not set session cookies")
		}
	}
	code := loc.Query().Get("code")
	if !strings.HasPrefix(code, "bsc_") || strings.Contains(loc.String(), "access_token") {
		t.Fatalf("code: %s", loc)
	}
	// Wrong verifier burns the code.
	e.expect(e.api("POST", "/v1/sso/exchange", map[string]string{"code": code, "code_verifier": strings.Repeat("x", 50)}), 400, "invalid_code")
	e.expect(e.api("POST", "/v1/sso/exchange", map[string]string{"code": code, "code_verifier": verifier}), 400, "invalid_code")

	res = e.oidcLogin("corp", m, user, q)
	loc, _ = url.Parse(res.Header.Get("Location"))
	code = loc.Query().Get("code")
	e.expect(e.api("POST", "/v1/sso/exchange", map[string]string{"code": code}), 400, "invalid_code") // verifier required
	res = e.oidcLogin("corp", m, user, q)
	loc, _ = url.Parse(res.Header.Get("Location"))
	code = loc.Query().Get("code")
	r := e.api("POST", "/v1/sso/exchange", map[string]string{"code": code, "code_verifier": verifier})
	e.expect(r, 200, "")
	if r.str("access_token") == "" || !strings.HasPrefix(r.str("refresh_token"), "bsr_") || r.str("user", "username") != "desk" || r.str("session_id") == "" {
		t.Fatalf("exchange: %s", r.raw)
	}
	// Untrusted provider: the email stays on the identity, not the account.
	if r.body["user"].(map[string]any)["email"] != nil {
		t.Fatalf("untrusted email copied to the account: %s", r.raw)
	}
	e.expect(e.api("POST", "/v1/sso/exchange", map[string]string{"code": code, "code_verifier": verifier}), 400, "invalid_code") // single use
	e.expect(e.api("GET", "/v1/me", nil, bearer(r.str("access_token"))), 200, "")
	if si := e.adminUser(adminAT, r.str("user", "id")); si["last_sign_in_method"] != "oidc:corp" || si["last_sign_in_at"] == nil {
		t.Fatalf("SSO code exchange sign-in not recorded: %v", si)
	}
	// Refresh works like any session.
	e.expect(e.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": r.str("refresh_token")}), 200, "")

	// Without PKCE the bare code is enough (contract: POST {code}).
	res = e.oidcLogin("corp", m, user, url.Values{"return_to": {"boson://sso/done"}})
	loc, _ = url.Parse(res.Header.Get("Location"))
	if loc.Scheme != "boson" {
		t.Fatalf("custom scheme: %s", loc)
	}
	e.expect(e.api("POST", "/v1/sso/exchange", map[string]string{"code": loc.Query().Get("code")}), 200, "")

	// Web app on another origin can ask for code mode explicitly; cookie
	// exchange then needs the CSRF header.
	res = e.oidcLogin("corp", m, user, url.Values{"return_to": {"/after"}, "mode": {"code"}})
	loc, _ = url.Parse(res.Header.Get("Location"))
	code = loc.Query().Get("code")
	e.expect(e.api("POST", "/v1/sso/exchange", map[string]any{"code": code, "cookie": true}), 403, "csrf")
	r = e.api("POST", "/v1/sso/exchange", map[string]any{"code": code, "cookie": true}, header("X-Requested-With", "x"))
	e.expect(r, 200, "")
	if r.str("access_token") != "" || len(r.header.Values("Set-Cookie")) != 2 {
		t.Fatalf("cookie exchange: %s %v", r.raw, r.header.Values("Set-Cookie"))
	}
}

func TestOIDCLinkingRules(t *testing.T) {
	e := newEnv(t)
	adminAT := e.adminToken("ssoadmin")
	m := mockIdP(t)
	trusted := e.oidcProvider(adminAT, "trusted", m, map[string]any{"trust_email": true, "allow_signup": false})
	e.oidcProvider(adminAT, "untrusted", m, map[string]any{"trust_email": false, "allow_signup": false})

	// A password account with a verified email links on a trusted IdP.
	bobID := e.registerVerified("bob", "bob@corp.example")
	res := e.oidcLogin("trusted", m, &mockoidc.MockUser{Subject: "b1", Email: "BOB@corp.example", EmailVerified: true}, url.Values{})
	if res.StatusCode != 303 || strings.Contains(res.Header.Get("Location"), "error") {
		t.Fatalf("trusted link: %s", res.Header.Get("Location"))
	}
	bobAT := e.login("bob", pw).str("access_token")
	idl := e.api("GET", "/v1/me/identities", nil, bearer(bobAT))
	if l := idl.list("identities"); len(l) != 1 || l[0]["provider_slug"] != "trusted" || idl.body["has_password"] != true {
		t.Fatalf("bob identities: %s", idl.raw)
	}
	a := e.api("GET", "/v1/admin/audit?event=sso_identity_linked&actor="+bobID, nil, bearer(adminAT))
	if len(a.list("entries")) != 1 {
		t.Fatalf("link not audited: %s", a.raw)
	}
	// With a password left, the identity can be unlinked.
	e.expect(e.api("DELETE", "/v1/me/identities/"+idl.list("identities")[0]["id"].(string), nil, bearer(bobAT)), 204, "")
	e.expect(e.api("DELETE", "/v1/me/identities/uid_nope", nil, bearer(bobAT)), 404, "not_found")

	// Unverified email at the IdP, or an untrusted IdP: no linking, and
	// sign-up is off → no_linked_account.
	for _, tc := range []struct {
		slug string
		user *mockoidc.MockUser
	}{
		{"trusted", &mockoidc.MockUser{Subject: "b2", Email: "bob@corp.example", EmailVerified: false}},
		{"untrusted", &mockoidc.MockUser{Subject: "b3", Email: "bob@corp.example", EmailVerified: true}},
	} {
		res = e.oidcLogin(tc.slug, m, tc.user, url.Values{})
		loc, _ := url.Parse(res.Header.Get("Location"))
		if loc.Query().Get("error") != "no_linked_account" || loc.Host != "app.integration.test" {
			t.Fatalf("%s: %s", tc.slug, loc)
		}
	}

	// An unverified account squatting an address is never linked: sign-up
	// creates a separate account without that email.
	e.expect(e.api("POST", "/v1/register", map[string]string{"username": "squatter", "email": "victim@corp.example", "password": pw}), 201, "")
	e.mail.next(t)
	e.expect(e.api("PATCH", "/v1/admin/sso/providers/"+trusted, map[string]any{"allow_signup": true}, bearer(adminAT)), 200, "")
	res = e.oidcLogin("trusted", m, &mockoidc.MockUser{Subject: "victim", Email: "victim@corp.example", EmailVerified: true, PreferredUsername: "squatter"}, url.Values{"mode": {"code"}})
	loc, _ := url.Parse(res.Header.Get("Location"))
	r := e.api("POST", "/v1/sso/exchange", map[string]string{"code": loc.Query().Get("code")})
	e.expect(r, 200, "")
	if r.str("user", "username") != "squatter2" || r.body["user"].(map[string]any)["email"] != nil {
		t.Fatalf("squatted email: %s", r.raw)
	}

	// Disabled accounts can't sign in through SSO either.
	e.expect(e.api("POST", "/v1/admin/users/"+r.str("user", "id")+"/disable", nil, bearer(adminAT)), 200, "")
	res = e.oidcLogin("trusted", m, &mockoidc.MockUser{Subject: "victim", Email: "victim@corp.example", EmailVerified: true}, url.Values{})
	loc, _ = url.Parse(res.Header.Get("Location"))
	if loc.Query().Get("error") != "account_disabled" {
		t.Fatalf("disabled: %s", loc)
	}
}

func TestOIDCRegistrationModes(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.AccountConfig.SettingsCacheTTL = 0 })
	adminAT := e.adminToken("ssoadmin")
	m := mockIdP(t)
	e.oidcProvider(adminAT, "idp", m, nil)
	errOf := func(res string) string { u, _ := url.Parse(res); return u.Query().Get("error") }

	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"registration": "closed"}, bearer(adminAT)), 200, "")
	res := e.oidcLogin("idp", m, &mockoidc.MockUser{Subject: "n1"}, url.Values{})
	if errOf(res.Header.Get("Location")) != "registration_closed" {
		t.Fatalf("closed: %s", res.Header.Get("Location"))
	}

	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"registration": "invite"}, bearer(adminAT)), 200, "")
	res = e.oidcLogin("idp", m, &mockoidc.MockUser{Subject: "n1"}, url.Values{})
	if errOf(res.Header.Get("Location")) != "invite_required" {
		t.Fatalf("invite without code: %s", res.Header.Get("Location"))
	}
	inv := e.api("POST", "/v1/admin/invites", map[string]any{"max_uses": 1}, bearer(adminAT)).str("invite", "code")
	res = e.oidcLogin("idp", m, &mockoidc.MockUser{Subject: "n1", PreferredUsername: "newbie"}, url.Values{"invite_code": {inv}})
	if res.StatusCode != 303 || errOf(res.Header.Get("Location")) != "" {
		t.Fatalf("invite: %s", res.Header.Get("Location"))
	}
	// Existing identities still log in when registration is closed.
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"registration": "closed"}, bearer(adminAT)), 200, "")
	res = e.oidcLogin("idp", m, &mockoidc.MockUser{Subject: "n1"}, url.Values{})
	if errOf(res.Header.Get("Location")) != "" {
		t.Fatalf("returning user under closed registration: %s", res.Header.Get("Location"))
	}
}

func TestSSOFlowRejections(t *testing.T) {
	e := newEnv(t)
	adminAT := e.adminToken("ssoadmin")
	m := mockIdP(t)
	e.oidcProvider(adminAT, "mock", m, nil)
	c := e.browser()

	// Bad return_to / mode / provider.
	for q, code := range map[string]string{
		"return_to=https://evil.example/":             "invalid_return_to",
		"return_to=//evil.example/":                   "invalid_return_to",
		"return_to=javascript:alert(1)":               "invalid_return_to",
		"return_to=http://127.0.0.1:1/&mode=cookie":   "invalid_request",
		"return_to=https://user@app.integration.test": "invalid_return_to",
	} {
		res, body := e.get(c, e.public.URL+"/v1/sso/mock/start?"+q)
		if res.StatusCode != 400 || !strings.Contains(body, code) {
			t.Fatalf("%s: %d %s", q, res.StatusCode, body)
		}
	}
	res, body := e.get(c, e.public.URL+"/v1/sso/nope/start")
	if loc, _ := url.Parse(res.Header.Get("Location")); res.StatusCode != 303 || loc.Query().Get("error") != "unknown_provider" {
		t.Fatalf("unknown provider: %d %s %s", res.StatusCode, res.Header.Get("Location"), body)
	}

	// Callback without the state cookie, or with a forged state.
	res, body = e.get(c, e.public.URL+"/v1/sso/mock/start")
	authz := location(t, res, body)
	res, body = e.get(c, authz.String())
	cb := location(t, res, body)
	forged := *cb
	q := forged.Query()
	q.Set("state", "forged")
	forged.RawQuery = q.Encode()
	res, body = e.get(c, e.local(forged.String()))
	if res.StatusCode != 400 || !strings.Contains(body, "invalid_state") {
		t.Fatalf("forged state: %d %s", res.StatusCode, body)
	}
	// The state cookie was single use: the genuine callback now fails too.
	res, body = e.get(c, e.local(cb.String()))
	if res.StatusCode != 400 || !strings.Contains(body, "invalid_state") {
		t.Fatalf("replayed callback: %d %s", res.StatusCode, body)
	}

	// The IdP reports an error (user cancelled).
	res, body = e.get(c, e.public.URL+"/v1/sso/mock/start?return_to=/x")
	authz = location(t, res, body)
	cancel := e.public.URL + "/v1/sso/mock/callback?error=access_denied&state=" + url.QueryEscape(authz.Query().Get("state"))
	res, body = e.get(c, cancel)
	if loc := location(t, res, body); loc.Query().Get("error") != "access_denied" || loc.Path != "/x" {
		t.Fatalf("cancel: %s", loc)
	}

	// A code that never existed.
	e.expect(e.api("POST", "/v1/sso/exchange", map[string]string{"code": "bsc_nope"}), 400, "invalid_code")
	e.expect(e.api("POST", "/v1/sso/exchange", map[string]string{"code": "something"}), 400, "invalid_code")
}

func TestAdminSSOProviders(t *testing.T) {
	e := newEnv(t)
	adminAT := e.adminToken("ssoadmin")
	m := mockIdP(t)
	e.registerVerified("plain", "plain@example.com")
	userAT := e.login("plain", pw).str("access_token")
	e.expect(e.api("GET", "/v1/admin/sso/providers", nil, bearer(userAT)), 403, "forbidden")

	// Validation.
	for _, bad := range []map[string]any{
		{"slug": "Bad Slug", "kind": "oidc", "config": map[string]any{"issuer": m.Issuer(), "client_id": "x"}},
		{"slug": "x", "kind": "ldap", "config": map[string]any{}},
		{"slug": "x", "kind": "oidc", "config": map[string]any{"client_id": "x"}},
		{"slug": "x", "kind": "oidc", "config": map[string]any{"issuer": "http://idp.example.com", "client_id": "x"}},
		{"slug": "x", "kind": "oidc", "config": map[string]any{"issuer": m.Issuer(), "client_id": "x", "typo": 1}},
		{"slug": "x", "kind": "saml", "config": map[string]any{}},
		{"slug": "x", "kind": "saml", "config": map[string]any{"idp_metadata_xml": "<nope/>"}},
		{"slug": "x", "kind": "saml", "config": map[string]any{"idp_metadata_url": "https://x", "client_secret": "s"}},
	} {
		e.expect(e.api("POST", "/v1/admin/sso/providers", bad, bearer(adminAT)), 400, "invalid_request")
	}

	r := e.api("POST", "/v1/admin/sso/providers", map[string]any{
		"slug": "google", "kind": "oidc", "display_name": "Google", "enabled": false, "allow_signup": true, "trust_email": true,
		"config": map[string]any{"issuer": m.Issuer(), "client_id": m.ClientID, "client_secret": m.ClientSecret, "scopes": []string{"email", "profile"}},
	}, bearer(adminAT))
	e.expect(r, 201, "")
	if strings.Contains(string(r.raw), m.ClientSecret) {
		t.Fatal("client secret returned")
	}
	p := r.body["provider"].(map[string]any)
	cfg := p["config"].(map[string]any)
	id := p["id"].(string)
	if p["has_client_secret"] != true || cfg["has_client_secret"] != true || cfg["issuer"] != m.Issuer() ||
		p["redirect_uri"] != e.cfg.HTTPConfig.PublicURL+"/v1/sso/google/callback" || p["start_url"] == "" ||
		len(cfg["scopes"].([]any)) != 3 || cfg["scopes"].([]any)[0] != "openid" || p["enabled"] != false {
		t.Fatalf("created: %s", r.raw)
	}
	e.expect(e.api("POST", "/v1/admin/sso/providers", map[string]any{"slug": "google", "kind": "oidc",
		"config": map[string]any{"issuer": m.Issuer(), "client_id": "x"}}, bearer(adminAT)), 409, "slug_taken")

	// Disabled providers aren't offered and can't start.
	if len(e.api("GET", "/v1/config", nil).list("sso_providers")) != 0 {
		t.Fatal("disabled provider listed")
	}
	// Test works on a disabled provider.
	tr := e.api("POST", "/v1/admin/sso/providers/"+id+"/test", nil, bearer(adminAT))
	e.expect(tr, 200, "")
	det := tr.body["details"].(map[string]any)
	if tr.body["ok"] != true || det["jwks_keys"].(float64) < 1 || det["token_endpoint"] == "" {
		t.Fatalf("test: %s", tr.raw)
	}

	// PATCH: partial config keeps the secret; enable.
	r = e.api("PATCH", "/v1/admin/sso/providers/"+id, map[string]any{"enabled": true, "config": map[string]any{"username_claim": "email"}}, bearer(adminAT))
	e.expect(r, 200, "")
	p = r.body["provider"].(map[string]any)
	if p["has_client_secret"] != true || p["config"].(map[string]any)["username_claim"] != "email" || p["config"].(map[string]any)["client_id"] != m.ClientID {
		t.Fatalf("patched: %s", r.raw)
	}
	if l := e.api("GET", "/v1/config", nil).list("sso_providers"); len(l) != 1 || l[0]["display_name"] != "Google" {
		t.Fatalf("enabled provider not listed: %v", l)
	}
	// It works end to end with the stored (encrypted) secret.
	res := e.oidcLogin("google", m, &mockoidc.MockUser{Subject: "g1", Email: "g@corp.example", EmailVerified: true}, url.Values{"mode": {"code"}})
	loc, _ := url.Parse(res.Header.Get("Location"))
	x := e.api("POST", "/v1/sso/exchange", map[string]string{"code": loc.Query().Get("code")})
	e.expect(x, 200, "")
	if x.str("user", "username") != "g_corp_example" { // username_claim = email, sanitized
		t.Fatalf("username from claim: %s", x.raw)
	}
	// Clearing the secret: the mock IdP then refuses the token request.
	r = e.api("PATCH", "/v1/admin/sso/providers/"+id, map[string]any{"config": map[string]any{"client_secret": ""}}, bearer(adminAT))
	if r.body["provider"].(map[string]any)["has_client_secret"] != false {
		t.Fatalf("secret not cleared: %s", r.raw)
	}
	res = e.oidcLogin("google", m, &mockoidc.MockUser{Subject: "g1"}, url.Values{})
	if l, _ := url.Parse(res.Header.Get("Location")); l.Query().Get("error") != "sso_failed" {
		t.Fatalf("without secret: %s", res.Header.Get("Location"))
	}
	e.expect(e.api("PATCH", "/v1/admin/sso/providers/"+id, map[string]any{"kind": "saml"}, bearer(adminAT)), 400, "invalid_request")
	e.expect(e.api("PATCH", "/v1/admin/sso/providers/"+id, map[string]any{}, bearer(adminAT)), 400, "invalid_request")

	// Unreachable issuer → ok:false with the reason.
	bad := e.api("POST", "/v1/admin/sso/providers", map[string]any{"slug": "down", "kind": "oidc",
		"config": map[string]any{"issuer": "http://127.0.0.1:1/", "client_id": "x"}}, bearer(adminAT))
	e.expect(bad, 201, "")
	tr = e.api("POST", "/v1/admin/sso/providers/"+bad.str("provider", "id")+"/test", nil, bearer(adminAT))
	if tr.body["ok"] != false || tr.body["details"].(map[string]any)["error"] == "" {
		t.Fatalf("test of a dead issuer: %s", tr.raw)
	}

	if l := e.api("GET", "/v1/admin/sso/providers", nil, bearer(adminAT)).list("providers"); len(l) != 2 {
		t.Fatalf("list: %v", l)
	}
	e.expect(e.api("GET", "/v1/admin/sso/providers/"+id, nil, bearer(adminAT)), 200, "")
	e.expect(e.api("DELETE", "/v1/admin/sso/providers/"+id, nil, bearer(adminAT)), 204, "")
	e.expect(e.api("GET", "/v1/admin/sso/providers/"+id, nil, bearer(adminAT)), 404, "not_found")
	e.expect(e.api("DELETE", "/v1/admin/sso/providers/"+id, nil, bearer(adminAT)), 404, "not_found")
	if len(e.api("GET", "/v1/config", nil).list("sso_providers")) != 0 {
		t.Fatal("deleted provider still listed")
	}
	a := e.api("GET", "/v1/admin/audit?event=sso_provider_created,sso_provider_updated,sso_provider_deleted&limit=200", nil, bearer(adminAT))
	if n := len(a.list("entries")); n != 5 {
		t.Fatalf("provider audit entries = %d: %s", n, a.raw)
	}
}
