package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	fedrepo "github.com/boson-chat/auth/internal/db/repositories/federation"
	"github.com/boson-chat/auth/internal/nick"
)

func TestHandleCandidates(t *testing.T) {
	got := handleCandidates("alice", "boson.chat")
	if got[0] != "alice" || got[1] != "alice-bosonchat" || got[2] != "alice-bosonchat2" || got[len(got)-1] != "alice-bosonchat20" {
		t.Fatalf("%v", got)
	}
	long := strings.Repeat("a", 30)
	for _, c := range handleCandidates(long, "a-very-long-domain-name.example.org") {
		if len(c) > nick.MaxLen || nick.Validate(c) != nil {
			t.Fatalf("invalid candidate %q", c)
		}
	}
	if c := handleCandidates("9lives.cat", "x.org"); c[0] != "u9lives_cat" {
		t.Fatalf("%v", c)
	}
	if c := handleCandidates("日本", "x.org"); c[0] != "user" || c[1] != "user-xorg" {
		t.Fatalf("%v", c)
	}
	if c := handleCandidates("NickServ", "x.org"); c[0] != "NickServ_" {
		t.Fatalf("reserved: %v", c)
	}
	if domainLabel("Chat.Example-Site.org") != "chatexamplesiteo" {
		t.Fatal(domainLabel("Chat.Example-Site.org"))
	}
	h, err := randomHandle("bob")
	if err != nil || !strings.HasPrefix(h, "bob") || len(h) != 8 {
		t.Fatalf("%q %v", h, err)
	}
}

func TestSettingsPatchAndSources(t *testing.T) {
	t.Setenv("FEDERATION_ALLOW", "a.org")
	s := newSettingsStore(nil, nil, nil, config.Config{FederationConfig: config.FederationConfig{
		Mode: "open", Allow: "a.org", RemoteVoice: true, RemoteUploadQuota: "1GB",
	}}, time.Now)
	row := &fedrepo.SettingsRow{}
	eff := s.effective(row)
	if eff.Mode != "open" || len(eff.Allow) != 1 || eff.remoteUploadBytes != 1e9 || eff.DirectoryURL != config.DefaultDirectoryURL ||
		!eff.Editable || eff.Block == nil || eff.Sources["allow"] != "env" || eff.Sources["mode"] != "default" {
		t.Fatalf("%+v", eff)
	}
	p := Patch{"mode": json.RawMessage(`"allowlist"`), "allow": json.RawMessage(`["B.org","*.c.org","b.org"]`),
		"remote_upload_quota": json.RawMessage(`""`), "remote_voice": json.RawMessage(`false`),
		"directory_url": json.RawMessage(`"https://dir.example.org/"`)}
	if err := s.apply(row, p); err != nil {
		t.Fatal(err)
	}
	eff = s.effective(row)
	if eff.Mode != "allowlist" || strings.Join(eff.Allow, ",") != "b.org,*.c.org" || eff.remoteUploadBytes != 0 || eff.RemoteVoice ||
		eff.DirectoryURL != "https://dir.example.org" || eff.Sources["mode"] != "database" || eff.Sources["block"] != "default" {
		t.Fatalf("%+v", eff)
	}
	if err := s.apply(row, Patch{"mode": json.RawMessage(`null`), "allow": json.RawMessage(`null`)}); err != nil {
		t.Fatal(err)
	}
	if eff = s.effective(row); eff.Mode != "open" || eff.Allow[0] != "a.org" {
		t.Fatalf("reset: %+v", eff)
	}
	for _, bad := range []Patch{
		{},
		{"mode": json.RawMessage(`"maybe"`)},
		{"mode": json.RawMessage(`1`)},
		{"allow": json.RawMessage(`"a.org"`)},
		{"block": json.RawMessage(`["*.org"]`)},
		{"directory_url": json.RawMessage(`"http://dir.example.org"`)},
		{"remote_upload_quota": json.RawMessage(`"lots"`)},
		{"remote_upload_quota": json.RawMessage(`5`)},
		{"remote_voice": json.RawMessage(`"yes"`)},
		{"domain": json.RawMessage(`"x.org"`)},
	} {
		if err := s.apply(&fedrepo.SettingsRow{}, bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	// File mode: the file's values, read-only.
	fc := config.FederationConfig{Mode: "off", Block: "x.org", RemoteUploadQuota: "2GB"}
	s.setFile(&fc, []string{"mode", "block"})
	eff, _ = s.get(context.Background())
	if eff.Mode != "off" || eff.Editable || eff.Sources["mode"] != "file" || eff.Sources["block"] != "file" || eff.remoteUploadBytes != 2e9 {
		t.Fatalf("file: %+v", eff)
	}
	if _, err := s.update(context.Background(), "", Patch{"mode": json.RawMessage(`"open"`)}); err != ErrSettingsManaged {
		t.Fatalf("update in file mode: %v", err)
	}
}

func TestPublicAddr(t *testing.T) {
	for a, want := range map[string]bool{
		"1.1.1.1": true, "2606:4700::1111": true, "127.0.0.1": false, "10.0.0.1": false, "192.168.1.2": false,
		"169.254.169.254": false, "::1": false, "fd00::1": false, "100.64.0.1": false, "0.0.0.0": false,
	} {
		if got := publicAddr(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: %v", a, got)
		}
	}
	c := NewHTTPClient(time.Second, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	if _, err := c.Get(srv.URL); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("loopback dial allowed: %v", err)
	}
}

// testClient routes every request to h (any host), over plain http even
// for https URLs.
func testClient(h http.Handler) *http.Client {
	srv := httptest.NewServer(h)
	addr := srv.Listener.Addr().String()
	return &http.Client{Transport: rewrite{addr: addr}}
}

type rewrite struct{ addr string }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = "http", r.addr
	return (&http.Transport{DialContext: (&net.Dialer{}).DialContext}).RoundTrip(req)
}

func jwk(kid string, pub ed25519.PublicKey) map[string]string {
	return map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": base64.RawURLEncoding.EncodeToString(pub), "use": "sig"}
}

func TestRemoteJWKSCacheAndRefetch(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	var keys atomic.Value
	keys.Store([]map[string]string{jwk("k1", pub1)})
	var fetches atomic.Int64
	client := testClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys.Load()})
	}))
	now := time.Now()
	clock := func() time.Time { return now }
	rm := newRemote(client, false, clock)
	ctx := context.Background()
	if k, err := rm.key(ctx, "https://h/jwks", "k1"); err != nil || !k.Equal(pub1) {
		t.Fatal(err)
	}
	if _, err := rm.key(ctx, "https://h/jwks", "k1"); err != nil || fetches.Load() != 1 {
		t.Fatalf("not cached: %d", fetches.Load())
	}
	// Rotation: unknown kid → refetch, throttled.
	keys.Store([]map[string]string{jwk("k1", pub1), jwk("k2", pub2)})
	if _, err := rm.key(ctx, "https://h/jwks", "k2"); err != errUnknownKey || fetches.Load() != 1 {
		t.Fatalf("refetch not throttled: %v %d", err, fetches.Load())
	}
	now = now.Add(jwksRefetchMinGap + time.Second)
	if k, err := rm.key(ctx, "https://h/jwks", "k2"); err != nil || !k.Equal(pub2) || fetches.Load() != 2 {
		t.Fatalf("refetch: %v %d", err, fetches.Load())
	}
	now = now.Add(jwksRefetchMinGap + time.Second)
	if _, err := rm.key(ctx, "https://h/jwks", "nope"); err != errUnknownKey {
		t.Fatal(err)
	}
}

func TestRemoteDiscoveryAndDirectory(t *testing.T) {
	var discHits, dirHits atomic.Int64
	var down atomic.Bool
	client := testClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/boson.json":
			discHits.Add(1)
			_, _ = io.WriteString(w, `{"version":1,"irc":{"host":"IRC.Home.Test."},"federation":{"version":1,"issuer":"https://auth.home.test",
				"jwks_uri":"https://auth.home.test/.well-known/jwks.json","accepts":"open"}}`)
		case r.URL.Path == "/v1/networks/lookup":
			dirHits.Add(1)
			if down.Load() {
				w.WriteHeader(503)
				return
			}
			h := r.URL.Query().Get("hostname")
			if h != "irc.home.test" {
				w.WriteHeader(404)
				return
			}
			_, _ = io.WriteString(w, `{"network":{"hostname":"irc.home.test","status":"verified"}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	now := time.Now()
	rm := newRemote(client, false, func() time.Time { return now })
	ctx := context.Background()
	d, err := rm.discovery(ctx, "home.test")
	if err != nil || d.Issuer != "https://auth.home.test" || d.IRCHost != "irc.home.test" || d.Accepts != "open" {
		t.Fatalf("%+v %v", d, err)
	}
	_, _ = rm.discovery(ctx, "home.test")
	if discHits.Load() != 1 {
		t.Fatal("discovery not cached")
	}
	ok, err := rm.listed(ctx, "https://dir", []string{"home.test", "irc.home.test"})
	if !ok || err != nil || dirHits.Load() != 2 {
		t.Fatalf("listed: %v %v %d", ok, err, dirHits.Load())
	}
	// The directory goes down after the cache expires: a verified listing
	// stays trusted (stale-if-error); an unknown one fails with an error.
	down.Store(true)
	now = now.Add(directoryTTL + time.Second)
	if ok, err := rm.listed(ctx, "https://dir", []string{"irc.home.test"}); !ok || err != nil {
		t.Fatalf("stale-if-error: %v %v", ok, err)
	}
	if ok, err := rm.listed(ctx, "https://dir", []string{"other.test"}); ok || err == nil {
		t.Fatalf("down directory: %v %v", ok, err)
	}
}

func TestFilesQuota(t *testing.T) {
	var got []string
	client := testClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+r.Header.Get("X-Internal-Token")+" "+strings.TrimSpace(string(b)))
		if r.Method == http.MethodDelete {
			w.WriteHeader(404)
		}
	}))
	f := newFilesQuota(config.FilesInternalConfig{URL: "http://files:3001/", Token: "tok"}, client)
	if !f.enabled() || newFilesQuota(config.FilesInternalConfig{URL: "http://files:3001"}, nil).enabled() {
		t.Fatal("enabled")
	}
	ctx := context.Background()
	if err := f.apply(ctx, "usr_1", 5e8, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.apply(ctx, "usr_1", 0, 0); err != nil {
		t.Fatal(err) // 404 on DELETE is fine
	}
	if got[0] != `PUT /internal/quota/usr_1 tok {"max_file_bytes":null,"quota_bytes":500000000}` || got[1] != "DELETE /internal/quota/usr_1 tok " {
		t.Fatalf("%q", got)
	}
	if quotaKey(0, 0) != "" || quotaKey(1, 0) != "1/0" {
		t.Fatal("quotaKey")
	}
}

func TestCleanProfile(t *testing.T) {
	if cleanPicture("http://x.org/a.png") != "" || cleanPicture("https://x.org/a.png") != "https://x.org/a.png" || cleanPicture("javascript:x") != "" {
		t.Fatal("picture")
	}
	if n := cleanName("  " + strings.Repeat("é", 80) + " "); len([]rune(n)) != 64 {
		t.Fatalf("name %q", n)
	}
}
