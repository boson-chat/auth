package middleware

import (
	"fmt"
	nethttp "net/http"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/reqmeta"
)

type statusRecorder struct {
	nethttp.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Unwrap() nethttp.ResponseWriter { return s.ResponseWriter }

// Logging attaches a request-scoped logger and logs each request. The query
// string is never logged.
func Logging(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		start := time.Now()
		reqID := ids.New("req")
		l := logger.FromCtx(r.Context()).With().Str("request_id", reqID).Logger()
		ctx := logger.WithLogger(r.Context(), l)
		rec := &statusRecorder{ResponseWriter: w, status: nethttp.StatusOK}
		w.Header().Set("X-Request-Id", reqID)
		next.ServeHTTP(rec, r.WithContext(ctx))
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics" {
			return
		}
		ev := l.Info()
		if rec.status >= 500 {
			ev = l.Error()
		}
		ev.Str("method", r.Method).Str("path", r.URL.Path).Int("status", rec.status).
			Str("ip", reqmeta.From(ctx).IP).Dur("duration", time.Since(start)).Msg("request")
	})
}

// Recover turns panics into 500s.
func Recover(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == nethttp.ErrAbortHandler {
					panic(v)
				}
				logger.FromCtx(r.Context()).Error().Str("panic", fmt.Sprint(v)).Bytes("stack", debug.Stack()).Msg("panic")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(nethttp.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"internal_error","message":"internal error"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders sets conservative defaults. Handlers may override
// Cache-Control (JWKS) and the CSP (HTML pages).
func SecurityHeaders(next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// CORS allows credentialed requests from the listed origins only.
func CORS(origins []string) func(nethttp.Handler) nethttp.Handler {
	allowed := TrimOrigins(origins)
	return DynamicCORS(func() []string { return allowed })
}

// TrimOrigins drops trailing slashes.
func TrimOrigins(origins []string) []string {
	allowed := make([]string, 0, len(origins))
	for _, o := range origins {
		allowed = append(allowed, strings.TrimRight(o, "/"))
	}
	return allowed
}

// DynamicCORS is CORS with the allowed origins read per request (they
// change when the stack config file is reloaded). origins must return
// trimmed origins (TrimOrigins).
func DynamicCORS(origins func() []string) func(nethttp.Handler) nethttp.Handler {
	return func(next nethttp.Handler) nethttp.Handler {
		return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			allowed := origins()
			origin := r.Header.Get("Origin")
			if origin != "" {
				w.Header().Add("Vary", "Origin")
			}
			if origin != "" && slices.Contains(allowed, origin) {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
				if r.Method == nethttp.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
					h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE")
					h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
					h.Set("Access-Control-Max-Age", "600")
					w.WriteHeader(nethttp.StatusNoContent)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Chain applies middleware so the first listed runs first.
func Chain(h nethttp.Handler, mw ...func(nethttp.Handler) nethttp.Handler) nethttp.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// PublicCORS serves the paths matched by public to every origin without
// credentials (Access-Control-Allow-Origin: *), answering their preflights
// itself; every other request goes through credentialed. Public responses
// are the same for everyone (the network's branding), so caches and
// clients on any origin may share them.
func PublicCORS(public func(path string) bool, credentialed func(nethttp.Handler) nethttp.Handler) func(nethttp.Handler) nethttp.Handler {
	return func(next nethttp.Handler) nethttp.Handler {
		cred := credentialed(next)
		return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			if !public(r.URL.Path) {
				cred.ServeHTTP(w, r)
				return
			}
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", "*")
			h.Set("Access-Control-Expose-Headers", "ETag")
			if r.Method == nethttp.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Set("Access-Control-Allow-Methods", "GET, HEAD")
				h.Set("Access-Control-Allow-Headers", "If-None-Match")
				h.Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(nethttp.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// PathPrefix matches path p and everything under p + "/".
func PathPrefix(p string) func(string) bool {
	return func(path string) bool { return path == p || strings.HasPrefix(path, p+"/") }
}

// BearerCORS serves CORS * without credentials on the paths match accepts
// (GET and POST with Authorization / Content-Type), for APIs that other
// origins call with a bearer token or a signed assertion in the request
// and never with cookies (federated login). Other paths go to rest.
func BearerCORS(match func(path string) bool, rest func(nethttp.Handler) nethttp.Handler) func(nethttp.Handler) nethttp.Handler {
	return func(next nethttp.Handler) nethttp.Handler {
		other := rest(next)
		return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			if !match(r.URL.Path) {
				other.ServeHTTP(w, r)
				return
			}
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", "*")
			if r.Method == nethttp.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h.Set("Access-Control-Allow-Methods", "GET, POST")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(nethttp.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
