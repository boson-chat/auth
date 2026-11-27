package integration

import (
	"encoding/json"
	"fmt"
	nethttp "net/http"
	"strings"
	"testing"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/services/federation"
)

// GET /v1/web-origins on the remote: its own web client, then the web
// clients of the directory's verified servers (from their boson.json).
func TestWebOriginsFromDirectory(t *testing.T) {
	f := newFed(t, func(c *config.Config) { c.HTTPConfig.WebClientURL = "https://chat.remote.test/" })
	f.net.handle("other.test", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		_, _ = fmt.Fprint(w, `{"version":1,"irc":{"host":"irc.other.test"},"web":{"url":"https://chat.other.test/"}}`)
	}))
	f.net.handle("evil.test", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		_, _ = fmt.Fprint(w, `{"version":1,"irc":{"host":"irc.evil.test"},"web":{"url":"https://chat.other.test.evil.test.attacker.example/"}}`)
	}))
	f.dir.set("irc.other.test", true)
	f.dir.set("irc.evil.test", true)
	f.dir.set("irc.home.test", true) // home.test's boson.json has no web section

	origins := func() []string {
		r := f.remote.api("GET", "/v1/web-origins", nil)
		f.remote.expect(r, 200, "")
		if cc := r.header.Get("Cache-Control"); cc != "public, max-age=60" {
			t.Fatalf("Cache-Control %q", cc)
		}
		var body federation.WebOrigins
		if err := json.Unmarshal(r.raw, &body); err != nil {
			t.Fatal(err)
		}
		return body.Origins
	}
	if got := strings.Join(origins(), " "); got != "https://chat.remote.test" {
		t.Fatalf("before the first build: %s", got)
	}
	svc := f.remote.app.Federation.(*federation.FederationService)
	if err := svc.RefreshWebOrigins(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(origins(), " "); got != "https://chat.remote.test https://chat.other.test" {
		t.Fatalf("after: %s", got)
	}
	// Unlisted: gone at the next build.
	f.dir.set("irc.other.test", false)
	if err := svc.RefreshWebOrigins(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(origins(), " "); got != "https://chat.remote.test" {
		t.Fatalf("unlisted: %s", got)
	}
}
