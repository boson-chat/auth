package integration

import (
	"context"
	"io"
	nethttp "net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
)

const brandingSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 2 2"><rect width="2" height="2" fill="#7c3aed"/></svg>`

func TestBrandingAndEmailsFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "boson.yaml")
	if err := os.Mkdir(filepath.Join(dir, "branding"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "branding", "logo-abc.svg"), []byte(brandingSVG), 0o644); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, path, `version: 1
network: { name: Example Chat }
branding:
  theme:
    base: dark
    colors: { accent: "#7c3aed" }
    panes:
      messages: { dim: 0.7, blur: 8, position: center }
  images:
    logo: logo-abc.svg
auth:
  email:
    sender_name: Example Chat
    accent: "#7c3aed"
    footer: Example Chat · example.com
    logo: true
    templates:
      verification: { subject: "Confirm your {{network}} account", body: "Hi {{username}},\n\n{{link}}\n\nExpires in {{expires}}." }
`)
	e := newEnv(t, func(c *config.Config) {
		c.AppConfig.ConfigFile = path
		c.AppConfig.ConfigPoll = 200 * time.Millisecond
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.app.StackConfig.Run(ctx)

	// Discovery and the document.
	c := e.api("GET", "/v1/config", nil)
	if c.str("branding_url") != "http://auth.integration.test/v1/branding" {
		t.Fatalf("/v1/config: %s", c.raw)
	}
	b := e.api("GET", "/v1/branding", nil, header("Origin", "https://other.example"))
	e.expect(b, 200, "")
	logo := b.str("logo")
	if !strings.HasPrefix(logo, "http://auth.integration.test/v1/branding/assets/logo-abc.svg?v=") ||
		b.header.Get("Access-Control-Allow-Origin") != "*" || b.header.Get("ETag") == "" {
		t.Fatalf("branding: %s %v", b.raw, b.header)
	}
	e.expect(e.api("GET", "/v1/branding", nil, header("If-None-Match", b.header.Get("ETag"))), 304, "")

	// The asset.
	res, err := nethttp.Get(e.public.URL + strings.TrimPrefix(logo, "http://auth.integration.test"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != brandingSVG || res.Header.Get("Content-Security-Policy") != "default-src 'none'; style-src 'unsafe-inline'" ||
		res.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("asset %d %v", res.StatusCode, res.Header)
	}
	for _, p := range []string{"/v1/branding/assets/..%2Fboson.yaml", "/v1/branding/assets/boson.yaml"} {
		if r, _ := nethttp.Get(e.public.URL + p); r.StatusCode == 200 {
			t.Fatalf("%s served", p)
		}
	}

	// Branded verification email with the file's wording.
	e.expect(e.api("POST", "/v1/register", map[string]string{"username": "newbie", "email": "newbie@example.com", "password": pw}), 201, "")
	msg := e.mail.next(t)
	if msg.Subject != "Confirm your Example Chat account" || msg.FromName != "Example Chat" ||
		!strings.Contains(msg.HTML, "logo-abc.svg?v=") || !strings.Contains(msg.HTML, "Hi newbie,") ||
		!strings.Contains(msg.Text, "Expires in 24 hours.") {
		t.Fatalf("%+v", msg)
	}

	// Preview / test: internal listener, settings.manage.
	adminAT := e.adminToken("brandadmin")
	userAT := e.roleToken("plainuser", "user")
	prev := map[string]any{"template": "password_reset", "subject": "Reset for {{username}}", "body": "<b>{{network}}</b>\n\n{{link}}"}
	e.expect(e.do(e.internal, "POST", "/internal/email/preview", prev), 401, "unauthenticated")
	e.expect(e.do(e.internal, "POST", "/internal/email/preview", prev, bearer(userAT)), 403, "forbidden")
	e.expect(e.api("POST", "/internal/email/preview", prev, bearer(adminAT)), 404, "") // not on the public listener
	p := e.do(e.internal, "POST", "/internal/email/preview", prev, bearer(adminAT))
	e.expect(p, 200, "")
	if p.str("subject") != "Reset for brandadmin" || !strings.Contains(p.str("html"), "&lt;b&gt;Example Chat&lt;/b&gt;") ||
		!strings.Contains(p.str("text"), "<b>Example Chat</b>") || !strings.Contains(p.str("html"), "Choose a new password") {
		t.Fatalf("preview: %s", p.raw)
	}
	e.expect(e.do(e.internal, "POST", "/internal/email/preview", map[string]any{"template": "nope"}, bearer(adminAT)), 400, "invalid_request")

	e.expect(e.do(e.internal, "POST", "/internal/email/test", map[string]any{"template": "verification", "to": "x"}, bearer(adminAT)), 400, "invalid_request")
	tr := e.do(e.internal, "POST", "/internal/email/test", map[string]any{"template": "verification", "to": "me@example.com"}, bearer(adminAT))
	e.expect(tr, 200, "")
	if tr.str("status") != "sent" || tr.str("to") != "me@example.com" || tr.str("subject") != "[Test] Confirm your Example Chat account" {
		t.Fatalf("test: %s", tr.raw)
	}
	if m := e.mail.next(t); m.To != "me@example.com" || !strings.HasPrefix(m.Subject, "[Test] ") {
		t.Fatalf("%+v", m)
	}
	a := e.api("GET", "/v1/admin/audit?event=email_test_sent", nil, bearer(adminAT))
	e.expect(a, 200, "")
	if entries := a.list("entries"); len(entries) != 1 || entries[0]["meta"].(map[string]any)["to"] != "me@example.com" ||
		entries[0]["actor_username"] != "brandadmin" {
		t.Fatalf("audit: %s", a.raw)
	}
	// Rate limit: the burst of 5 (one used above, one rejected as invalid).
	limited := false
	for range 6 {
		r := e.do(e.internal, "POST", "/internal/email/test", map[string]any{"template": "invite", "to": "me@example.com"}, bearer(adminAT))
		if r.status == 429 {
			limited = true
			if r.header.Get("Retry-After") == "" {
				t.Fatal("Retry-After")
			}
			break
		}
		e.expect(r, 200, "")
		e.mail.next(t)
	}
	if !limited {
		t.Fatal("test emails must be rate-limited")
	}

	// Live reload: branding removed → no document, built-in emails again.
	writeConfig(t, path, "version: 1\nnetwork: { name: Example Chat }\n")
	eventually(t, "branding removed", func() bool { return e.api("GET", "/v1/branding", nil).status == 404 })
	if c := e.api("GET", "/v1/config", nil); c.body["branding_url"] != nil {
		t.Fatalf("/v1/config: %s", c.raw)
	}
	e.expect(e.api("POST", "/v1/email/resend", map[string]string{"email": "newbie@example.com"}), 202, "")
	if msg := e.mail.next(t); msg.Subject != "Verify your email for Example Chat" || msg.FromName != "" ||
		!strings.HasPrefix(msg.HTML, "<!doctype html>\n<html><body") {
		t.Fatalf("%+v", msg)
	}
}

func TestBrandingWithoutConfigFile(t *testing.T) {
	e := newEnv(t)
	e.expect(e.api("GET", "/v1/branding", nil), 404, "no_branding")
	if c := e.api("GET", "/v1/config", nil); c.body["branding_url"] != nil {
		t.Fatalf("/v1/config: %s", c.raw)
	}
	// Preview works without a file (Boson's built-in emails).
	adminAT := e.adminToken("admin0")
	p := e.do(e.internal, "POST", "/internal/email/preview", map[string]any{"template": "account_setup"}, bearer(adminAT))
	e.expect(p, 200, "")
	if !strings.HasPrefix(p.str("subject"), "Your ") || p.str("html") == "" || p.str("text") == "" {
		t.Fatalf("%s", p.raw)
	}
	tr := e.do(e.internal, "POST", "/internal/email/test", map[string]any{"template": "account_setup", "to": "me@example.com"}, bearer(adminAT))
	e.expect(tr, 200, "")
	e.mail.next(t)
}
