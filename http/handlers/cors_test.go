package handlers

import "testing"

func TestTokenAPIPaths(t *testing.T) {
	open := []string{
		"/v1/config", "/v1/login", "/v1/register", "/v1/email/resend", "/v1/password/forgot", "/v1/password/change",
		"/v1/sso/exchange", "/v1/token/refresh", "/v1/logout", "/v1/me", "/v1/me/identities", "/v1/me/identities/abc",
		"/v1/me/privacy", "/v1/me/channels", "/v1/voice/token", "/v1/voice/guest-token", "/v1/sessions", "/v1/sessions/s1",
		"/v1/friends", "/v1/friends/requests", "/v1/friends/requests/u1/accept", "/v1/friends/u1", "/v1/blocks", "/v1/blocks/u1",
		"/v1/calls", "/v1/calls/c1/token", "/v1/calls/missed", "/v1/calls/missed/seen", "/v1/events",
		"/v1/users/alice/relation", "/v1/roles", "/v1/users/roles",
	}
	for _, p := range open {
		if !TokenAPIPaths(p) {
			t.Errorf("%s must be on the token API", p)
		}
	}
	closed := []string{
		"/v1/admin/users", "/v1/admin/settings", "/v1/sso/okta/start", "/v1/sso/okta/callback", "/v1/sso/okta/saml/acs",
		"/v1/sso/okta/saml/metadata", "/v1/email/verify", "/v1/password/reset", "/v1/register/confirm", "/verify-email",
		"/reset-password", "/v1/branding", "/v1/users//relation", "/v1/users/alice/relation/x", "/v1/users/alice",
		"/v1/mex", "/healthz", "/internal/v1/settings",
	}
	for _, p := range closed {
		if TokenAPIPaths(p) {
			t.Errorf("%s must not be on the token API", p)
		}
	}
}

func TestAnyOriginPaths(t *testing.T) {
	on, off := AnyOriginPaths(true), AnyOriginPaths(false)
	if !on("/v1/login") || off("/v1/login") {
		t.Fatal("CORS_ANY_ORIGIN must switch the token API")
	}
	for _, p := range []string{"/v1/federation/login", "/v1/federation/assertions", federationMetadataPath, "/v1/users/identities", "/v1/users/a/identity"} {
		if !on(p) || !off(p) {
			t.Fatalf("federation %s must stay open", p)
		}
	}
	if on("/v1/admin/users") || on("/v1/sso/x/start") {
		t.Fatal("cookie paths must stay closed")
	}
}
