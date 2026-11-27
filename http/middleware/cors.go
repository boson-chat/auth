package middleware

import (
	nethttp "net/http"
	"slices"
	"strings"
)

// Headers of the any-origin (CORS *) token API.
const (
	TokenCORSMethods = "GET, POST, PUT, PATCH, DELETE"
	TokenCORSHeaders = "Authorization, Content-Type, Accept, If-None-Match"
	TokenCORSExpose  = "Retry-After, ETag, X-Request-Id"
	// TokenCORSMaxAge: how long browsers may cache a preflight (seconds;
	// Chromium caps it at 2 h, Firefox at 24 h).
	TokenCORSMaxAge = "86400"
)

// TokenCORS serves the bearer-token JSON API (the paths open accepts) to
// web apps on any origin.
//
//   - An origin trusted returns (the credentialed CORS allowlist) gets the
//     credentialed treatment of rest, exactly as on every other path.
//   - Any other caller gets Access-Control-Allow-Origin: * without
//     credentials, and preflights are answered here (204).
//
// A browser never lets a page read a response to a credentialed request
// that came back with ACAO *, and refuses to send a credentialed
// preflighted request at all. On top of that, requests from an untrusted
// origin (Origin set, not trusted, not self) are made cookie-free here:
// their Cookie header is dropped before the handler runs and any
// Set-Cookie it writes is dropped from the response. So the dual-mode
// endpoints (login / refresh / logout / me accept the boson_at / boson_rt
// cookies, cookie: true sets them) behave as pure bearer endpoints for
// other origins, and cookie sessions stay reachable from the allowlist
// (and auth's own origin, self) only.
//
// Paths open rejects go to rest unchanged.
func TokenCORS(open func(path string) bool, trusted func() []string, self string,
	rest func(nethttp.Handler) nethttp.Handler,
) func(nethttp.Handler) nethttp.Handler {
	self = strings.TrimRight(self, "/")
	return func(next nethttp.Handler) nethttp.Handler {
		other := rest(next)
		return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			if !open(r.URL.Path) {
				other.ServeHTTP(w, r)
				return
			}
			origin := r.Header.Get("Origin")
			if origin != "" && (origin == self || slices.Contains(trusted(), origin)) {
				other.ServeHTTP(w, r)
				return
			}
			h := w.Header()
			// Trusted origins get different headers on these paths.
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Access-Control-Expose-Headers", TokenCORSExpose)
			if r.Method == nethttp.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Set("Access-Control-Allow-Methods", TokenCORSMethods)
				h.Set("Access-Control-Allow-Headers", TokenCORSHeaders)
				h.Set("Access-Control-Max-Age", TokenCORSMaxAge)
				w.WriteHeader(nethttp.StatusNoContent)
				return
			}
			if origin == "" {
				// Not a readable cross-origin browser request (fetch
				// in cors mode always sends Origin): same-origin GETs,
				// native apps, servers.
				next.ServeHTTP(w, r)
				return
			}
			r = r.Clone(r.Context())
			r.Header.Del("Cookie")
			next.ServeHTTP(&noCookieWriter{ResponseWriter: w}, r)
		})
	}
}

// noCookieWriter drops Set-Cookie from the response.
type noCookieWriter struct {
	nethttp.ResponseWriter
	wrote bool
}

func (n *noCookieWriter) strip() {
	if !n.wrote {
		n.wrote = true
		n.ResponseWriter.Header().Del("Set-Cookie")
	}
}

func (n *noCookieWriter) WriteHeader(code int) {
	n.strip()
	n.ResponseWriter.WriteHeader(code)
}

func (n *noCookieWriter) Write(b []byte) (int, error) {
	n.strip()
	return n.ResponseWriter.Write(b)
}

// Flush keeps streaming responses working.
func (n *noCookieWriter) Flush() {
	n.strip()
	if f, ok := n.ResponseWriter.(nethttp.Flusher); ok {
		f.Flush()
	}
}

func (n *noCookieWriter) Unwrap() nethttp.ResponseWriter { return n.ResponseWriter }
