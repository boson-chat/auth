package handlers

import (
	"encoding/json"
	nethttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/http/middleware"
	"github.com/boson-chat/auth/internal/services/branding"
	"github.com/boson-chat/auth/internal/theme"
)

const testSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><script>alert(1)</script></svg>`

// A 1×1 GIF.
var testGIF = []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")

func brandingServer(t *testing.T, configured bool) (nethttp.Handler, *branding.BrandingService) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string][]byte{"logo.svg": []byte(testSVG), "bg.gif": testGIF, "secret.gif": testGIF} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	svc := branding.NewBrandingService("https://auth.example.com")
	if configured {
		snap, err := branding.Prepare(&config.BrandingConfig{
			Theme:  theme.Theme{Version: 1, Base: "dark", Colors: map[string]string{"accent": "#7c3aed"}},
			Images: []config.BrandingImage{{Slot: "logo", File: "logo.svg"}, {Slot: "login_background", File: "bg.gif"}},
		}, dir, "https://auth.example.com")
		if err != nil {
			t.Fatal(err)
		}
		svc.Set(snap)
	}
	h := &Handlers{Branding: svc}
	mux := nethttp.NewServeMux()
	h.registerBranding(mux)
	return middleware.Chain(mux, middleware.SecurityHeaders,
		middleware.PublicCORS(middleware.PathPrefix(branding.DocumentPath),
			middleware.DynamicCORS(func() []string { return []string{"https://app.example.com"} }))), svc
}

func get(h nethttp.Handler, method, target string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestBrandingDocumentETagAndCORS(t *testing.T) {
	h, _ := brandingServer(t, true)
	w := get(h, "GET", "/v1/branding", "Origin", "https://elsewhere.example")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatal(w.Code, w.Body.String())
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Access-Control-Allow-Credentials") != "" ||
		w.Header().Get("Access-Control-Expose-Headers") != "ETag" {
		t.Fatal(w.Header())
	}
	// Even an origin allowed for credentials gets the public answer.
	if w2 := get(h, "GET", "/v1/branding", "Origin", "https://app.example.com"); w2.Header().Get("Access-Control-Allow-Origin") != "*" ||
		w2.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal(w2.Header())
	}
	if w.Header().Get("Cache-Control") != "public, max-age=60" {
		t.Fatal(w.Header().Get("Cache-Control"))
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	logo, _ := doc["logo"].(string)
	if !strings.HasPrefix(logo, "https://auth.example.com/v1/branding/assets/logo.svg?v=") || doc["colors"].(map[string]any)["accent"] != "#7c3aed" {
		t.Fatal(w.Body.String())
	}
	etag := w.Header().Get("ETag")
	for _, inm := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		nm := get(h, "GET", "/v1/branding", "If-None-Match", inm)
		if nm.Code != 304 || nm.Body.Len() != 0 || nm.Header().Get("ETag") != etag {
			t.Fatalf("If-None-Match %s: %d", inm, nm.Code)
		}
	}
	if get(h, "GET", "/v1/branding", "If-None-Match", `"stale"`).Code != 200 {
		t.Fatal("stale ETag → 200")
	}
	if hd := get(h, "HEAD", "/v1/branding"); hd.Code != 200 || hd.Body.Len() != 0 || hd.Header().Get("ETag") != etag {
		t.Fatal("HEAD", hd.Code)
	}
	// Preflight (a client sending If-None-Match itself).
	pf := get(h, "OPTIONS", "/v1/branding", "Origin", "https://app.example.com", "Access-Control-Request-Method", "GET",
		"Access-Control-Request-Headers", "if-none-match")
	if pf.Code != 204 || pf.Header().Get("Access-Control-Allow-Origin") != "*" || pf.Header().Get("Access-Control-Allow-Headers") != "If-None-Match" {
		t.Fatal(pf.Code, pf.Header())
	}
}

func TestBrandingNotConfigured(t *testing.T) {
	h, _ := brandingServer(t, false)
	w := get(h, "GET", "/v1/branding")
	if w.Code != 404 || !strings.Contains(w.Body.String(), "no_branding") || w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal(w.Code, w.Body.String())
	}
	if get(h, "GET", "/v1/branding/assets/logo.svg").Code != 404 {
		t.Fatal("no assets without branding")
	}
	// No branding service wired at all.
	mux := nethttp.NewServeMux()
	(&Handlers{}).registerBranding(mux)
	if w := get(mux, "GET", "/v1/branding"); w.Code != 404 {
		t.Fatal(w.Code)
	}
	if w := get(mux, "GET", "/v1/branding/assets/logo.svg"); w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestBrandingAssetHeaders(t *testing.T) {
	h, svc := brandingServer(t, true)
	doc, _ := svc.Document(t.Context())
	logoURL := strings.TrimPrefix(doc.Theme.Logo, "https://auth.example.com")
	w := get(h, "GET", logoURL)
	if w.Code != 200 || w.Body.String() != testSVG {
		t.Fatal(w.Code, w.Body.String())
	}
	hd := w.Header()
	if hd.Get("Content-Type") != "image/svg+xml" || hd.Get("X-Content-Type-Options") != "nosniff" ||
		hd.Get("Content-Security-Policy") != "default-src 'none'; style-src 'unsafe-inline'" ||
		hd.Get("Cache-Control") != "public, max-age=31536000, immutable" || hd.Get("Access-Control-Allow-Origin") != "*" ||
		hd.Get("Cross-Origin-Resource-Policy") != "cross-origin" {
		t.Fatal(hd)
	}
	// Without (or with an old) ?v= the cache is short.
	for _, u := range []string{"/v1/branding/assets/logo.svg", "/v1/branding/assets/logo.svg?v=old"} {
		if c := get(h, "GET", u).Header().Get("Cache-Control"); c != "public, max-age=300" {
			t.Fatal(u, c)
		}
	}
	etag := hd.Get("ETag")
	if nm := get(h, "GET", logoURL, "If-None-Match", etag); nm.Code != 304 {
		t.Fatal("asset ETag", nm.Code)
	}
	gif := get(h, "GET", "/v1/branding/assets/bg.gif")
	if gif.Code != 200 || gif.Header().Get("Content-Type") != "image/gif" ||
		gif.Header().Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'" {
		t.Fatal(gif.Code, gif.Header())
	}
}

func TestBrandingAssetTraversal(t *testing.T) {
	h, _ := brandingServer(t, true)
	for _, p := range []string{
		"/v1/branding/assets/secret.gif",             // in the directory but not referenced
		"/v1/branding/assets/..%2Fboson.yaml",        // encoded slash
		"/v1/branding/assets/..%2f..%2fetc%2fpasswd", // lower-case encoding
		"/v1/branding/assets/%2e%2e%2fsecret.gif",    // encoded dots
		"/v1/branding/assets/logo.svg%00.png",        // NUL
		"/v1/branding/assets/.logo.svg",              // dot file
		"/v1/branding/assets/logo.svg/",              // trailing slash
		"/v1/branding/assets/sub%2Flogo.svg",         // subdirectory
		"/v1/branding/assets/%5C..%5Csecret.gif",     // backslashes
		"/v1/branding/assets/LOGO.SVG",               // other name
		"/v1/branding/assets/",                       // no name
		"/v1/branding/assets/logo.svg%3F.png",        // encoded ?
		"/v1/branding/assets/" + strings.Repeat("a", 200) + ".png",
	} {
		w := get(h, "GET", p)
		if w.Code == 200 {
			t.Errorf("%s served", p)
		}
		if w.Code != 404 && w.Code != 301 && w.Code != 307 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	// Dot-dot paths are cleaned (redirected) by the mux before any handler runs.
	if w := get(h, "GET", "/v1/branding/assets/../../boson.yaml"); w.Code == 200 {
		t.Fatal("traversal served")
	}
}
