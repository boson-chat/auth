package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
)

func TestNormalizeOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://chat.example.org":          "https://chat.example.org",
		"https://chat.example.org/":         "https://chat.example.org",
		"HTTPS://Chat.Example.ORG/app/x?a":  "",
		"https://Chat.Example.ORG/app/":     "https://chat.example.org",
		"https://chat.example.org.":         "https://chat.example.org",
		"https://chat.example.org:443/":     "https://chat.example.org",
		"https://chat.example.org:8443":     "https://chat.example.org:8443",
		"https://chat.example.org:0":        "",
		"https://chat.example.org:99999":    "",
		"https://chat.example.org:":         "",
		"http://chat.example.org":           "",
		"https://user@chat.example.org":     "",
		"https://chat.example.org/#x":       "",
		"https://1.2.3.4":                   "",
		"https://localhost":                 "",
		"https://exa_mple.org":              "",
		"chat.example.org":                  "",
		"":                                  "",
		"javascript:alert(1)":               "",
		"  https://chat.example.org/path  ": "https://chat.example.org",
	} {
		got, ok := NormalizeOrigin(in, false)
		if got != want || ok != (want != "") {
			t.Errorf("NormalizeOrigin(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	// allowHTTP: the admin's own WEB_CLIENT_URL in development.
	for in, want := range map[string]string{
		"http://localhost:5173/": "http://localhost:5173",
		"http://LOCALHOST:80":    "http://localhost",
		"http://127.0.0.1:3000":  "http://127.0.0.1:3000",
		"http://[::1]:3000":      "http://[::1]:3000",
		"https://chat.x.org/":    "https://chat.x.org",
		"ftp://chat.x.org":       "",
	} {
		if got, _ := NormalizeOrigin(in, true); got != want {
			t.Errorf("NormalizeOrigin(%q, http) = %q, want %q", in, got, want)
		}
	}
}

// webNet is a fake directory (directory.test) and boson.json per domain,
// reached through testClient (routed by Host).
type webNet struct {
	mu sync.Mutex
	// listings: hostname → status, in name order.
	listings [][2]string
	// docs: domain → boson.json body ("" = 404; "500" = HTTP 500).
	docs     map[string]string
	dirDown  bool
	dirHits  atomic.Int64
	docHits  map[string]int
	pageSize int
}

func (n *webNet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	host := strings.Split(r.Host, ":")[0]
	if host == "directory.test" {
		n.dirHits.Add(1)
		if r.URL.Path != "/v1/networks" || n.dirDown {
			w.WriteHeader(503)
			return
		}
		q := r.URL.Query()
		if q.Get("nsfw") != "true" || q.Get("sort") != "name" {
			w.WriteHeader(400)
			return
		}
		start := 0
		if c := q.Get("cursor"); c != "" {
			_, _ = fmt.Sscanf(c, "c%d", &start)
		}
		end := min(start+n.pageSize, len(n.listings))
		var nets []map[string]any
		for _, l := range n.listings[start:end] {
			nets = append(nets, map[string]any{"hostname": l[0], "status": l[1]})
		}
		var next any
		if end < len(n.listings) {
			next = fmt.Sprintf("c%d", end)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"networks": nets, "next_cursor": next})
		return
	}
	if r.URL.Path != "/.well-known/boson.json" {
		w.WriteHeader(404)
		return
	}
	n.docHits[host]++
	switch d := n.docs[host]; d {
	case "":
		w.WriteHeader(404)
	case "500":
		w.WriteHeader(500)
	default:
		_, _ = io.WriteString(w, d)
	}
}

func (n *webNet) set(f func(n *webNet)) {
	n.mu.Lock()
	f(n)
	n.mu.Unlock()
}

func newWebOriginsService(t *testing.T, n *webNet, webClientURL, dirURL string) *FederationService {
	t.Helper()
	s := NewFederationService(Deps{Config: config.Config{HTTPConfig: config.HTTPConfig{WebClientURL: webClientURL}}, HTTPClient: testClient(n)})
	s.settings.setFile(&config.FederationConfig{Mode: config.FederationDirectory, DirectoryURL: dirURL}, nil)
	return s
}

func web(irc, url string) string {
	return fmt.Sprintf(`{"version":1,"irc":{"host":%q},"web":{"url":%q}}`, irc, url)
}

func TestWebOrigins(t *testing.T) {
	n := &webNet{pageSize: 2, docHits: map[string]int{}, listings: [][2]string{
		{"irc.a.test", "verified"},      // a.test: web at chat.a.test
		{"b.test", "verified"},          // listed by its bare domain
		{"irc.c.test", "verified"},      // no web client
		{"irc.d.test", "pending"},       // not verified
		{"irc.e.test", "verified"},      // web on another domain: ignored
		{"irc.f.test", "verified"},      // boson.json for another IRC network
		{"irc.g.test", "verified"},      // http web URL: ignored
		{"irc.libera.test", "verified"}, // plain IRC network, no boson.json
		{"IRC.H.Test.", "verified"},     // case and trailing dot
		{"irc.i.test", "verified"},      // server down (500)
		{"irc.a.test", "verified"},      // duplicate
	}, docs: map[string]string{
		"a.test": web("irc.a.test", "https://Chat.A.test/"),
		"b.test": web("b.test", "https://web.b.test:8443/app"),
		"c.test": `{"version":1,"irc":{"host":"irc.c.test"}}`,
		"d.test": web("irc.d.test", "https://chat.d.test"),
		"e.test": web("irc.e.test", "https://chat.evil.test"),
		"f.test": web("irc.other.test", "https://chat.f.test"),
		"g.test": web("irc.g.test", "http://chat.g.test"),
		"h.test": web("irc.h.test", "https://h.test"),
		"i.test": "500",
	}}
	s := newWebOriginsService(t, n, "https://Chat.Home.test/", "https://directory.test/")
	ctx := context.Background()

	// Before the first build: the own origin only.
	got, _ := s.WebOrigins(ctx)
	if strings.Join(got.Origins, " ") != "https://chat.home.test" || got.UpdatedAt != nil || got.Own != "https://chat.home.test" {
		t.Fatalf("before: %+v", got)
	}
	if err := s.RefreshWebOrigins(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ = s.WebOrigins(ctx)
	want := "https://chat.home.test https://chat.a.test https://h.test https://web.b.test:8443"
	if strings.Join(got.Origins, " ") != want || got.UpdatedAt == nil || got.Directory != "https://directory.test" {
		t.Fatalf("got %+v\nwant %s", got, want)
	}
	if n.docHits["d.test"] != 0 {
		t.Fatal("fetched a pending listing's boson.json")
	}
	// irc.libera.test: libera.test (404), then irc.libera.test itself.
	if n.docHits["libera.test"] != 1 || n.docHits["irc.libera.test"] != 1 {
		t.Fatalf("fallback: %v", n.docHits)
	}

	// A newly verified server shows up at the next refresh; one that
	// dropped its web client goes.
	n.set(func(n *webNet) {
		n.listings = append(n.listings, [2]string{"irc.new.test", "verified"})
		n.docs["new.test"] = web("irc.new.test", "https://chat.new.test")
		n.docs["h.test"] = `{"version":1,"irc":{"host":"irc.h.test"}}`
	})
	if err := s.RefreshWebOrigins(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ = s.WebOrigins(ctx)
	if want := "https://chat.home.test https://chat.a.test https://chat.new.test https://web.b.test:8443"; strings.Join(got.Origins, " ") != want {
		t.Fatalf("after: %v", got.Origins)
	}

	// A server down (5xx) keeps its last origin; the directory down
	// keeps the whole list.
	n.set(func(n *webNet) { n.docs["a.test"] = "500" })
	if err := s.RefreshWebOrigins(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ = s.WebOrigins(ctx)
	if !slices.Contains(got.Origins, "https://chat.a.test") {
		t.Fatalf("stale-if-error: %v", got.Origins)
	}
	before := got.UpdatedAt
	n.set(func(n *webNet) { n.dirDown = true })
	if err := s.RefreshWebOrigins(ctx); err == nil {
		t.Fatal("directory down: no error")
	}
	got, _ = s.WebOrigins(ctx)
	if !slices.Contains(got.Origins, "https://chat.new.test") || !got.UpdatedAt.Equal(*before) {
		t.Fatalf("directory down: %+v", got)
	}

	// A server that answers 404 now (no boson.json) is dropped.
	n.set(func(n *webNet) { n.dirDown = false; n.docs["new.test"] = "" })
	_ = s.RefreshWebOrigins(ctx)
	if got, _ = s.WebOrigins(ctx); slices.Contains(got.Origins, "https://chat.new.test") {
		t.Fatalf("404 kept: %v", got.Origins)
	}
}

func TestWebOriginsHTTPDirectoryAndEmpty(t *testing.T) {
	n := &webNet{pageSize: 10, docHits: map[string]int{}}
	// An http directory is refused (no FEDERATION_ALLOW_HTTP); without
	// WEB_CLIENT_URL the list is empty, still a JSON array.
	s := newWebOriginsService(t, n, "", "http://directory.test")
	if err := s.RefreshWebOrigins(context.Background()); err == nil || n.dirHits.Load() != 0 {
		t.Fatalf("http directory accepted: %v", err)
	}
	got, _ := s.WebOrigins(context.Background())
	b, _ := json.Marshal(got)
	if len(got.Origins) != 0 || got.Own != "" || !strings.Contains(string(b), `"origins":[]`) || !strings.Contains(string(b), `"updated_at":null`) {
		t.Fatalf("%s", b)
	}
}

func TestRunWebOriginsStopsAndRetries(t *testing.T) {
	n := &webNet{pageSize: 10, docHits: map[string]int{}, dirDown: true}
	s := newWebOriginsService(t, n, "https://chat.home.test", "https://directory.test")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.RunWebOrigins(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for n.dirHits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n.dirHits.Load() == 0 {
		t.Fatal("no first build")
	}
	got, _ := s.WebOrigins(ctx)
	if strings.Join(got.Origins, " ") != "https://chat.home.test" {
		t.Fatalf("%v", got.Origins)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunWebOrigins didn't stop")
	}
}
