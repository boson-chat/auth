package integration

import (
	"context"
	"fmt"
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
    variants:
      light: { colors: { accent: "#6d28d9" }, panes: { messages: { dim: 0.3 } } }
  images:
    logo: logo-abc.svg
    variants.light.panes.messages.image: logo-abc.svg
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
	if !strings.Contains(string(b.raw), `"variants":{"light":{"colors":{"accent":"#6d28d9"},"panes":{"messages":{"image":"`+logo+`","dim":0.3}}}}`) {
		t.Fatalf("variants: %s", b.raw)
	}

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
	if p.str("from") == "" || !strings.HasPrefix(p.str("from"), `"Example Chat" <`) || !strings.Contains(p.str("html"), `bgcolor="#7c3aed"`) {
		t.Fatalf("preview from / accent: %s", p.raw)
	}
	e.expect(e.do(e.internal, "POST", "/internal/email/preview", map[string]any{"template": "nope"}, bearer(adminAT)), 400, "invalid_request")
	// Unsaved email settings on top of the saved ones (live preview).
	live := map[string]any{"template": "verification", "email": map[string]any{"sender_name": "Typed Name", "accent": "#0EA5E9", "logo": false}}
	p = e.do(e.internal, "POST", "/internal/email/preview", live, bearer(adminAT))
	e.expect(p, 200, "")
	if !strings.HasPrefix(p.str("from"), `"Typed Name" <`) || !strings.Contains(p.str("html"), `bgcolor="#0ea5e9"`) ||
		strings.Contains(p.str("html"), "<img") || !strings.Contains(p.str("html"), ">Typed Name</span>") ||
		p.str("subject") != "Confirm your Example Chat account" || !strings.Contains(p.str("text"), "Example Chat · example.com") {
		t.Fatalf("live preview: %s", p.raw)
	}
	bad := e.do(e.internal, "POST", "/internal/email/preview", map[string]any{"template": "verification", "email": map[string]any{"accent": "blue"}}, bearer(adminAT))
	e.expect(bad, 400, "invalid_request")
	if bad.str("field") != "email.accent" || !strings.HasPrefix(bad.str("message"), "email.accent must be") {
		t.Fatalf("field-level error: %s", bad.raw)
	}
	e.expect(e.do(e.internal, "POST", "/internal/email/preview", map[string]any{"template": "verification", "email": map[string]any{"logo": "yes"}}, bearer(adminAT)), 400, "invalid_request")

	// Unsaved compiled MJML (layout and whole email) and its warnings.
	layoutHTML := "<html><body><div>{{content}}</div><p>{{nope}}</p></body></html>"
	p = e.do(e.internal, "POST", "/internal/email/preview", map[string]any{"template": "verification", "layout_html": layoutHTML}, bearer(adminAT))
	e.expect(p, 200, "")
	if ws, _ := p.body["warnings"].([]any); len(ws) != 1 || !strings.Contains(p.str("html"), "<div><p") || !strings.Contains(p.str("html"), "{{nope}}") {
		t.Fatalf("layout_html preview: %s", p.raw)
	}
	p = e.do(e.internal, "POST", "/internal/email/preview", map[string]any{"template": "invite", "html": `<a href="{{link}}">Join {{network}}</a>`}, bearer(adminAT))
	e.expect(p, 200, "")
	if ws, ok := p.body["warnings"].([]any); !ok || len(ws) != 0 || !strings.HasPrefix(p.str("html"), `<a href="http`) || !strings.HasSuffix(p.str("html"), ">Join Example Chat</a>") {
		t.Fatalf("html preview: %s", p.raw)
	}
	for field, body := range map[string]map[string]any{
		"layout_html": {"template": "verification", "layout_html": "<p>none</p>"},
		"html":        {"template": "verification", "html": "<p>no link</p>"},
	} {
		bad := e.do(e.internal, "POST", "/internal/email/preview", body, bearer(adminAT))
		e.expect(bad, 400, "invalid_request")
		if bad.str("field") != field {
			t.Fatalf("%s: %s", field, bad.raw)
		}
	}
	// 512 KB per document fits the preview body limit; one byte more is a 400.
	big := "{{content}}" + strings.Repeat("x", 512<<10-len("{{content}}"))
	e.expect(e.do(e.internal, "POST", "/internal/email/preview", map[string]any{"template": "verification", "layout_html": big}, bearer(adminAT)), 200, "")
	bad = e.do(e.internal, "POST", "/internal/email/preview", map[string]any{"template": "verification", "layout_html": big + "x"}, bearer(adminAT))
	e.expect(bad, 400, "invalid_request")
	if bad.str("field") != "layout_html" {
		t.Fatalf("size: %s", bad.raw)
	}

	// Boson's default MJML: same auth as preview.
	e.expect(e.do(e.internal, "GET", "/internal/email/default-mjml?part=layout", nil), 401, "unauthenticated")
	e.expect(e.do(e.internal, "GET", "/internal/email/default-mjml?part=layout", nil, bearer(userAT)), 403, "forbidden")
	e.expect(e.api("GET", "/internal/email/default-mjml?part=layout", nil, bearer(adminAT)), 404, "")
	for _, part := range []string{"layout", "verification", "password_reset", "account_setup", "invite"} {
		d := e.do(e.internal, "GET", "/internal/email/default-mjml?part="+part, nil, bearer(adminAT))
		e.expect(d, 200, "")
		if m := d.str("mjml"); !strings.HasPrefix(m, "<mjml") || (part == "layout") != strings.Contains(m, "{{content}}") || (part != "layout") != strings.Contains(m, `href="{{link}}"`) {
			t.Fatalf("%s: %s", part, d.raw)
		}
	}
	d := e.do(e.internal, "GET", "/internal/email/default-mjml?part=welcome", nil, bearer(adminAT))
	e.expect(d, 400, "invalid_request")
	if d.str("field") != "part" {
		t.Fatalf("%s", d.raw)
	}

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
	// Previews are limited too, but generously (a burst of 60 per admin):
	// a typing admin is never stopped; a runaway loop is.
	limited = false
	for i := range 100 {
		r := e.do(e.internal, "POST", "/internal/email/preview", map[string]any{"template": "invite", "body": fmt.Sprintf("draft %d", i)}, bearer(adminAT))
		if r.status == 429 {
			if i < 40 {
				t.Fatalf("preview limited after %d", i)
			}
			limited = r.header.Get("Retry-After") != ""
			break
		}
		e.expect(r, 200, "")
	}
	if !limited {
		t.Fatal("previews must be rate-limited")
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
