package middleware

import (
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tokenCORSHandler: /api/* is the open (any-origin) API, the rest goes
// through the credentialed allowlist. The handler echoes the Cookie it
// saw and tries to set one.
func tokenCORSHandler(allow []string, seen *string) nethttp.Handler {
	open := func(p string) bool { return strings.HasPrefix(p, "/api/") }
	h := nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		*seen = r.Header.Get("Cookie")
		nethttp.SetCookie(w, &nethttp.Cookie{Name: "boson_at", Value: "tok"})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(nethttp.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	return TokenCORS(open, func() []string { return allow }, "https://auth.example.com/", DynamicCORS(func() []string { return allow }))(h)
}

func do(h nethttp.Handler, method, path string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestTokenCORSPreflightAnyOrigin(t *testing.T) {
	var seen string
	h := tokenCORSHandler([]string{"https://app.example.com"}, &seen)
	w := do(h, "OPTIONS", "/api/login", "Origin", "https://chat.other.example", "Access-Control-Request-Method", "POST",
		"Access-Control-Request-Headers", "authorization, content-type")
	hd := w.Header()
	if w.Code != 204 || hd.Get("Access-Control-Allow-Origin") != "*" || hd.Get("Access-Control-Allow-Credentials") != "" ||
		hd.Get("Access-Control-Allow-Methods") != TokenCORSMethods || hd.Get("Access-Control-Allow-Headers") != TokenCORSHeaders ||
		hd.Get("Access-Control-Max-Age") != TokenCORSMaxAge || hd.Get("Vary") != "Origin" {
		t.Fatalf("%d %v", w.Code, hd)
	}
	for _, want := range []string{"Authorization", "Content-Type", "Accept"} {
		if !strings.Contains(hd.Get("Access-Control-Allow-Headers"), want) {
			t.Fatalf("allow headers missing %s", want)
		}
	}
	for _, want := range []string{"GET", "POST", "PATCH", "DELETE"} {
		if !strings.Contains(hd.Get("Access-Control-Allow-Methods"), want) {
			t.Fatalf("allow methods missing %s", want)
		}
	}
	if seen != "" {
		t.Fatal("preflight must not reach the handler")
	}
	// OPTIONS without Access-Control-Request-Method isn't a preflight.
	w = do(h, "OPTIONS", "/api/login", "Origin", "https://chat.other.example")
	if w.Code != 200 {
		t.Fatalf("plain OPTIONS: %d", w.Code)
	}
}

func TestTokenCORSActualRequestAnyOriginIsCookieFree(t *testing.T) {
	var seen string
	h := tokenCORSHandler([]string{"https://app.example.com"}, &seen)
	w := do(h, "POST", "/api/login", "Origin", "https://chat.other.example", "Cookie", "boson_at=victim")
	hd := w.Header()
	if w.Code != 200 || hd.Get("Access-Control-Allow-Origin") != "*" || hd.Get("Access-Control-Allow-Credentials") != "" ||
		hd.Get("Access-Control-Expose-Headers") != TokenCORSExpose || hd.Get("Access-Control-Allow-Methods") != "" {
		t.Fatalf("%d %v", w.Code, hd)
	}
	if seen != "" {
		t.Fatalf("cookie reached the handler: %q", seen)
	}
	if hd.Get("Set-Cookie") != "" {
		t.Fatalf("Set-Cookie leaked: %v", hd)
	}
}

func TestTokenCORSNoOrigin(t *testing.T) {
	// Native apps, servers, same-origin GETs: * (harmless) and untouched.
	var seen string
	h := tokenCORSHandler(nil, &seen)
	w := do(h, "GET", "/api/config", "Cookie", "boson_at=x")
	if w.Header().Get("Access-Control-Allow-Origin") != "*" || seen != "boson_at=x" || w.Header().Get("Set-Cookie") == "" {
		t.Fatalf("%v seen=%q", w.Header(), seen)
	}
}

func TestTokenCORSAllowlistKeepsCredentials(t *testing.T) {
	var seen string
	h := tokenCORSHandler([]string{"https://app.example.com"}, &seen)
	w := do(h, "OPTIONS", "/api/login", "Origin", "https://app.example.com", "Access-Control-Request-Method", "POST")
	hd := w.Header()
	if w.Code != 204 || hd.Get("Access-Control-Allow-Origin") != "https://app.example.com" || hd.Get("Access-Control-Allow-Credentials") != "true" ||
		!strings.Contains(hd.Get("Access-Control-Allow-Headers"), "X-Requested-With") {
		t.Fatalf("%d %v", w.Code, hd)
	}
	w = do(h, "POST", "/api/login", "Origin", "https://app.example.com", "Cookie", "boson_rt=r")
	hd = w.Header()
	if hd.Get("Access-Control-Allow-Origin") != "https://app.example.com" || hd.Get("Access-Control-Allow-Credentials") != "true" ||
		seen != "boson_rt=r" || hd.Get("Set-Cookie") == "" {
		t.Fatalf("%v seen=%q", hd, seen)
	}
}

func TestTokenCORSSelfOriginKeepsCookies(t *testing.T) {
	var seen string
	h := tokenCORSHandler(nil, &seen)
	w := do(h, "POST", "/api/logout", "Origin", "https://auth.example.com", "Cookie", "boson_rt=r")
	if seen != "boson_rt=r" || w.Header().Get("Set-Cookie") == "" || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("%v seen=%q", w.Header(), seen)
	}
}

func TestTokenCORSOtherPathsStayOnAllowlist(t *testing.T) {
	var seen string
	h := tokenCORSHandler([]string{"https://app.example.com"}, &seen)
	// A cookie path (not open): foreign origins get nothing, the
	// preflight falls through to the mux (405 there).
	w := do(h, "OPTIONS", "/v1/sso/x/start", "Origin", "https://evil.example", "Access-Control-Request-Method", "POST")
	if w.Header().Get("Access-Control-Allow-Origin") != "" || w.Code == 204 {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	w = do(h, "GET", "/v1/admin/users", "Origin", "https://evil.example", "Cookie", "boson_at=x")
	if w.Header().Get("Access-Control-Allow-Origin") != "" || seen != "boson_at=x" {
		t.Fatalf("%v", w.Header())
	}
	w = do(h, "GET", "/v1/admin/users", "Origin", "https://app.example.com")
	if w.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("%v", w.Header())
	}
}

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flushRecorder) Flush() { f.flushed = true }

func TestNoCookieWriter(t *testing.T) {
	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	n := &noCookieWriter{ResponseWriter: rec}
	n.Header().Set("Set-Cookie", "a=b")
	n.Flush()
	if !rec.flushed || rec.Header().Get("Set-Cookie") != "" {
		t.Fatalf("flush: %v %v", rec.flushed, rec.Header())
	}
	if n.Unwrap() != rec {
		t.Fatal("unwrap")
	}
	// Write without WriteHeader strips too; a writer without Flush is fine.
	plain := httptest.NewRecorder()
	n = &noCookieWriter{ResponseWriter: struct{ nethttp.ResponseWriter }{plain}}
	n.Header().Set("Set-Cookie", "a=b")
	_, _ = n.Write([]byte("x"))
	n.Flush()
	if plain.Header().Get("Set-Cookie") != "" || plain.Body.String() != "x" {
		t.Fatalf("%v", plain.Header())
	}
}
