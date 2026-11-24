package handlers

import "strings"

// verifyReturnTo validates a verification email's return_to against the
// same policy as SSO: one of this site's web origins (APP_URL, PUBLIC_URL,
// CORS_ALLOWED_ORIGINS) or an SSO_RETURN_TO_ALLOWED pattern (by default
// loopback and boson://). Anything else is dropped (""), never an error, so
// a client asking for a target the operator hasn't allowed still gets its
// account and its email; the page then falls back to verifiedRedirect's
// default.
func (h *Handlers) verifyReturnTo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || h.ReturnTo == nil {
		return ""
	}
	u, _, err := h.ReturnTo.Resolve(raw, "")
	if err != nil {
		return ""
	}
	return u
}

// verifiedRedirect is where the verify page sends the user after success:
// the (re-validated) return_to, else WEB_CLIENT_URL, else "" (the page
// offers to open the app instead).
func (h *Handlers) verifiedRedirect(returnTo string) string {
	if u := h.verifyReturnTo(returnTo); u != "" {
		return u
	}
	return strings.TrimSpace(h.Config.HTTPConfig.WebClientURL)
}
