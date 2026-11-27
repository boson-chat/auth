package handlers

import "strings"

// tokenAPIExact are the bearer-token JSON endpoints any Boson web client
// calls from its own origin (see client auth.service.ts / friends.api.ts):
// tokens travel in the Authorization header or the JSON body.
var tokenAPIExact = map[string]bool{
	"/v1/config":            true,
	"/v1/register":          true,
	"/v1/email/resend":      true,
	"/v1/login":             true,
	"/v1/token/refresh":     true,
	"/v1/logout":            true,
	"/v1/password/forgot":   true,
	"/v1/password/change":   true,
	"/v1/sso/exchange":      true,
	"/v1/voice/token":       true,
	"/v1/voice/guest-token": true,
	"/v1/sessions":          true,
	"/v1/roles":             true,
	"/v1/users/roles":       true,
	"/v1/friends":           true,
	"/v1/blocks":            true,
	"/v1/calls":             true,
	"/v1/events":            true,
	"/v1/me":                true,
}

// tokenAPIPrefixes: everything under these (all h.authed bearer routes).
var tokenAPIPrefixes = []string{"/v1/me/", "/v1/sessions/", "/v1/friends/", "/v1/blocks/", "/v1/calls/"}

// TokenAPIPaths is the bearer-token API served CORS * when
// CORS_ANY_ORIGIN is on. Not in it: /v1/admin/* (the admin panel, an
// allowlisted origin), the SSO browser flow /v1/sso/{slug}/* (redirects
// and the boson_sso state cookie), and the link pages' endpoints
// (/v1/email/verify, /v1/password/reset, /v1/register/confirm, called from
// auth's own /verify-email and /reset-password pages or the APP_URL app).
func TokenAPIPaths(path string) bool {
	if tokenAPIExact[path] {
		return true
	}
	for _, p := range tokenAPIPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	// GET /v1/users/{username}/relation
	if rest, ok := strings.CutPrefix(path, "/v1/users/"); ok {
		name, tail, _ := strings.Cut(rest, "/")
		return name != "" && tail == "relation"
	}
	return false
}

// AnyOriginPaths are the paths served CORS * to every origin but the
// credentialed allowlist: federation always (other servers' apps must
// reach it), the token API when anyOrigin (CORS_ANY_ORIGIN) is on.
func AnyOriginPaths(anyOrigin bool) func(path string) bool {
	return func(path string) bool {
		return FederationPaths(path) || (anyOrigin && TokenAPIPaths(path))
	}
}
