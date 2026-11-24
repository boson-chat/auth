package email

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	auditrepo "github.com/boson-chat/auth/internal/db/repositories/audit"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/mailer"
	"github.com/boson-chat/auth/metrics"
)

type capture struct {
	mu   sync.Mutex
	msgs []mailer.Message
	err  error
}

func (c *capture) Send(_ context.Context, m mailer.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m)
	return c.err
}

func (c *capture) bySubject(prefix string) mailer.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.msgs {
		if strings.HasPrefix(m.Subject, prefix) {
			return m
		}
	}
	return mailer.Message{}
}

type auditSpy struct {
	mu     sync.Mutex
	events []string
	actors []string
	metas  []map[string]any
}

func (a *auditSpy) Record(_ context.Context, actor, event string, meta map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events, a.actors, a.metas = append(a.events, event), append(a.actors, actor), append(a.metas, meta)
}
func (a *auditSpy) RecordTarget(ctx context.Context, actor, _, event string, meta map[string]any) {
	a.Record(ctx, actor, event, meta)
}
func (a *auditSpy) List(context.Context, auditrepo.Filter) ([]*auditrepo.EntryView, error) {
	return nil, nil
}

const site = "Example <Net> & Co"

func newSvc(m mailer.Mailer, logo string, a *auditSpy) *EmailService {
	opts := Options{AppURL: "https://app.example.com", SiteName: site, Logo: func() Logo { return Logo{URL: logo} },
		VerifyTTL: 24 * time.Hour, ResetTTL: 30 * time.Minute, SetupTTL: 72 * time.Hour, InviteTTL: 168 * time.Hour}
	if a != nil {
		opts.Audit = a
	}
	return NewEmailService(m, metrics.Noop(), opts).(*EmailService)
}

func sendAll(s *EmailService) {
	email := "a@example.com"
	u := &user.User{ID: "usr_1", Username: "alice<b>", Email: &email}
	ctx := context.Background()
	s.SendVerification(ctx, u, "tok/1+2", 24*time.Hour, "")
	s.SendPasswordReset(ctx, u, "tok/1+2", 30*time.Minute)
	s.SendAccountSetup(ctx, u, "tok/1+2", 72*time.Hour)
	s.Wait()
}

// Without auth.email the emails are exactly what auth sent before branding
// existed (golden files rendered by the previous implementation).
func TestDefaultsAreByteIdentical(t *testing.T) {
	for _, cfg := range []*config.EmailConfig{nil} {
		m := &capture{}
		s := newSvc(m, "https://auth.example.com/v1/branding/assets/logo.png?v=1", nil)
		s.SetConfig(cfg)
		sendAll(s)
		for name, prefix := range map[string]string{"verify": "Verify", "reset": "Reset", "setup": "Your"} {
			msg := m.bySubject(prefix)
			for ext, got := range map[string]string{"subject": msg.Subject, "txt": msg.Text, "html": msg.HTML, "link": msg.Link} {
				want, err := os.ReadFile("testdata/legacy/" + name + "." + ext)
				if err != nil {
					t.Fatal(err)
				}
				if got != string(want) {
					t.Errorf("%s.%s differs\n got %q\nwant %q", name, ext, got, want)
				}
			}
			if msg.FromName != "" {
				t.Errorf("%s: no sender name without auth.email", name)
			}
		}
	}
}

func TestBrandedLayoutUsesBrandingAndDefaultWording(t *testing.T) {
	m := &capture{}
	s := newSvc(m, "https://auth.example.com/v1/branding/assets/wide.png?v=abc", nil)
	s.SetConfig(&config.EmailConfig{SenderName: "Example Chat", Accent: "#7c3aed", Footer: "Example Chat · https://example.com", Logo: true})
	sendAll(s)
	msg := m.bySubject("Confirm your email for ")
	if msg.Subject != "Confirm your email for "+site {
		t.Fatalf("subject %q", msg.Subject)
	}
	if msg.FromName != "Example Chat" {
		t.Fatal("sender name", msg.FromName)
	}
	h := msg.HTML
	for _, want := range []string{
		`$&#160;verify --email`,
		`>Confirm your email for Example &lt;Net&gt; &amp; Co</div>`,
		`<img src="https://auth.example.com/v1/branding/assets/wide.png?v=abc" alt="Example Chat"`,
		`Hi alice&lt;b&gt;,`,
		`your Example &lt;Net&gt; &amp; Co account`,
		`href="https://app.example.com/verify-email#token=tok%2F1%2B2" style="display:inline-block;background:#7c3aed;color:#ffffff;`,
		`bgcolor="#7c3aed"`,
		"Confirm email\n",
		`Button not working? Paste this link into your browser:<br><a href="https://app.example.com/verify-email#token=tok%2F1%2B2"`,
		`Example Chat · <a href="https://example.com" style="color:#8e8e9e`,
		`Powered by <a href="https://boson.chat"`,
		`The link expires in 24 hours`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML lacks %q\n%s", want, h)
		}
	}
	if strings.Contains(h, "<b>") || strings.Contains(h, "<Net>") {
		t.Fatal("user data must be escaped")
	}
	wantText := "$ verify --email\n\nHi alice<b>,\n\nConfirm this address to finish setting up your " + site + " account.\n\n" +
		"Confirm email:\nhttps://app.example.com/verify-email#token=tok%2F1%2B2\n\n" +
		"The link expires in 24 hours and works once. If you didn't sign up, you can ignore this email.\n\n-- \nExample Chat · https://example.com\n"
	if msg.Text != wantText {
		t.Fatalf("text\n got %q\nwant %q", msg.Text, wantText)
	}
	// logo: false → the sender name as text, no image.
	s.SetConfig(&config.EmailConfig{SenderName: "Example Chat"})
	r, _ := s.Preview(context.Background(), "bob", PreviewInput{Template: config.EmailPasswordReset})
	if strings.Contains(r.HTML, "<img") || !strings.Contains(r.HTML, `color:#e2e2ea">Example Chat</span>`) ||
		!strings.Contains(r.HTML, "background:"+DefaultAccent) || strings.Contains(r.Text, "-- \n") {
		t.Fatal(r.HTML, r.Text)
	}
	// No sender name: the network name.
	s.SetConfig(&config.EmailConfig{})
	r, _ = s.Preview(context.Background(), "bob", PreviewInput{Template: config.EmailAccountSetup})
	if !strings.Contains(r.HTML, `color:#e2e2ea">Example &lt;Net&gt; &amp; Co</span>`) {
		t.Fatal(r.HTML)
	}
}

func TestTemplateOverridesVariablesAndEscaping(t *testing.T) {
	m := &capture{}
	s := newSvc(m, "", nil)
	subject := "Confirm {{ network }} for {{username}} {{unknown}}"
	body := "Hi {{username}} <script>alert(1)</script>,\n\n" +
		"Click {{link}} now.\nOr read https://example.com/help?a=1&b=2. Thanks!\n\n\n" +
		"{{link}}\n\n" +
		"{{inviter}} says hi; expires in {{expires}}; keep {{unknown}} and {{ network}x}} and {{Network}}."
	s.SetConfig(&config.EmailConfig{Templates: map[string]config.EmailTemplate{config.EmailVerification: {Subject: &subject, Body: &body}}})
	sendAll(s)
	msg := m.bySubject("Confirm ")
	if msg.Subject != "Confirm "+site+" for alice<b> {{unknown}}" {
		t.Fatalf("subject %q", msg.Subject)
	}
	h := msg.HTML
	for _, want := range []string{
		`Hi alice&lt;b&gt; &lt;script&gt;alert(1)&lt;/script&gt;,`,
		`Click <a href="https://app.example.com/verify-email#token=tok%2F1%2B2" style="color:#d97706;word-break:break-all">https://app.example.com/verify-email#token=tok%2F1%2B2</a> now.<br>`,
		`Or read <a href="https://example.com/help?a=1&amp;b=2" style="color:#d97706;word-break:break-all">https://example.com/help?a=1&amp;b=2</a>. Thanks!`,
		"Confirm email\n",
		` says hi; expires in 24 hours; keep {{unknown}} and {{ network}x}} and {{Network}}.`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML lacks %q\n%s", want, h)
		}
	}
	if strings.Contains(h, "<script>") {
		t.Fatal("template text must be escaped")
	}
	if strings.Count(h, `<p style="margin:0 0 16px 0">`) != 3 || strings.Count(h, `class="bx-btn `) != 1 || strings.Count(h, `class="bx-note `) != 1 {
		t.Fatalf("blank lines split paragraphs (3 + the button): %s", h)
	}
	if !strings.Contains(msg.Text, "Hi alice<b> <script>alert(1)</script>,\n\nClick https://app.example.com/verify-email#token=tok%2F1%2B2 now.\nOr read") ||
		!strings.Contains(msg.Text, "keep {{unknown}} and") {
		t.Fatalf("text %q", msg.Text)
	}
	// Other templates keep Boson's wording in the branded layout.
	if r := m.bySubject("Reset your "); !strings.Contains(r.HTML, "Choose a new password") || !strings.Contains(r.HTML, `xmlns:v="urn:schemas-microsoft-com:vml"`) {
		t.Fatal(r.HTML)
	}
}

func TestLinkifyIgnoresNonHTTPAndTrailingPunctuation(t *testing.T) {
	got := linkify(`see javascript:alert(1) and (https://a.example/x). or "https://b.example/y"`, "#000000")
	if strings.Contains(got, `href="javascript`) {
		t.Fatal(got)
	}
	if !strings.Contains(got, `(<a href="https://a.example/x" `) || !strings.Contains(got, `</a>).`) {
		t.Fatal(got)
	}
	if !strings.Contains(got, `&#34;<a href="https://b.example/y" `) {
		t.Fatal(got)
	}
}

func TestPreview(t *testing.T) {
	s := newSvc(&capture{}, "", nil)
	ctx := context.Background()
	// Nothing configured: the built-in email, exactly as it would be sent.
	r, err := s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification})
	if err != nil {
		t.Fatal(err)
	}
	if r.Subject != "Verify your email for "+site || !strings.HasPrefix(r.HTML, "<!doctype html>\n<html><body") ||
		!strings.Contains(r.Text, "https://app.example.com/verify-email#token=example-token") {
		t.Fatalf("%+v", r)
	}
	// Unsaved wording.
	sub, body := "Hello {{username}}", "Welcome to {{network}}.\n\n{{link}}"
	r, err = s.Preview(ctx, "admin", previewIn(config.EmailInvite, &config.EmailTemplate{Subject: &sub, Body: &body}))
	if err != nil {
		t.Fatal(err)
	}
	if r.Subject != "Hello admin" || !strings.Contains(r.HTML, "Welcome to Example &lt;Net&gt; &amp; Co.") ||
		!strings.Contains(r.HTML, `href="https://app.example.com/#invite=inv_example"`) || !strings.Contains(r.HTML, "Accept invite") {
		t.Fatalf("%+v", r)
	}
	// Invite default (no legacy template): branded even without auth.email.
	r, _ = s.Preview(ctx, "admin", PreviewInput{Template: config.EmailInvite})
	if r.Subject != "admin invited you to "+site || !strings.Contains(r.Text, "expires in 7 days") {
		t.Fatalf("%+v", r)
	}
	// Empty override = none.
	r, _ = s.Preview(ctx, "admin", previewIn(config.EmailPasswordReset, &config.EmailTemplate{}))
	if !strings.HasPrefix(r.HTML, "<!doctype html>\n<html><body") || !strings.Contains(r.Text, "30 minutes") {
		t.Fatal(r.HTML)
	}
	bad := "two\nlines"
	empty := " "
	for _, over := range []*config.EmailTemplate{{Subject: &bad}, {Body: &empty}} {
		if _, err := s.Preview(ctx, "admin", previewIn(config.EmailVerification, over)); !isInvalid(err) {
			t.Fatal(err)
		}
	}
	if _, err := s.Preview(ctx, "admin", PreviewInput{Template: "welcome"}); !errors.Is(err, ErrUnknownTemplate) {
		t.Fatal(err)
	}
}

func isInvalid(err error) bool {
	e, ok := apperr.As(err)
	return ok && e.Code == "invalid_request"
}

func TestSendTest(t *testing.T) {
	m := &capture{}
	a := &auditSpy{}
	s := newSvc(m, "", a)
	s.SetConfig(&config.EmailConfig{SenderName: "Example Chat"})
	ctx := context.Background()
	r, err := s.SendTest(ctx, "usr_admin", config.EmailAccountSetup, "admin", "me@example.com")
	if err != nil {
		t.Fatal(err)
	}
	msg := m.bySubject("[Test] ")
	if msg.To != "me@example.com" || msg.Subject != "[Test] Your "+site+" account is ready" || r.Subject != msg.Subject || msg.FromName != "Example Chat" ||
		!strings.Contains(msg.Text, "example-token") {
		t.Fatalf("%+v", msg)
	}
	if len(a.events) != 1 || a.events[0] != "email_test_sent" || a.actors[0] != "usr_admin" ||
		a.metas[0]["template"] != config.EmailAccountSetup || a.metas[0]["to"] != "me@example.com" || a.metas[0]["outcome"] != "success" {
		t.Fatalf("%v %v", a.events, a.metas)
	}
	for _, to := range []string{"", "not an address", "Me <me@example.com>", "me@example.com, you@example.com", "a\r\nBcc: x@example.com"} {
		if _, err := s.SendTest(ctx, "usr_admin", config.EmailVerification, "admin", to); !isInvalid(err) {
			t.Errorf("%q: %v", to, err)
		}
	}
	if _, err := s.SendTest(ctx, "usr_admin", "nope", "admin", "me@example.com"); !errors.Is(err, ErrUnknownTemplate) {
		t.Fatal(err)
	}
	m.err = errors.New("550 relay denied")
	_, err = s.SendTest(ctx, "usr_admin", config.EmailVerification, "admin", "me@example.com")
	if e, ok := apperr.As(err); !ok || e.Status != 502 || e.Code != "email_send_failed" || !strings.Contains(e.Message, "550 relay denied") {
		t.Fatal(err)
	}
	if len(a.events) != 2 || a.metas[1]["outcome"] != "error" {
		t.Fatal(a.metas)
	}
	if s.Logging() {
		t.Fatal("capture mailer is not the log mailer")
	}
	if !newSvc(mailer.NewSwappable(mailer.LogMailer{}), "", nil).Logging() {
		t.Fatal("log mailer behind Swappable")
	}
}

func TestReloadSwitchesBackToDefaults(t *testing.T) {
	m := &capture{}
	s := newSvc(m, "", nil)
	sub := "Custom"
	s.SetConfig(&config.EmailConfig{Templates: map[string]config.EmailTemplate{config.EmailVerification: {Subject: &sub}}})
	r, _ := s.Preview(context.Background(), "x", PreviewInput{Template: config.EmailVerification})
	if r.Subject != "Custom" {
		t.Fatal(r.Subject)
	}
	s.SetConfig(nil)
	sendAll(s)
	want, _ := os.ReadFile("testdata/legacy/verify.html")
	if m.bySubject("Verify").HTML != string(want) {
		t.Fatal("removing auth.email restores the built-in emails")
	}
}

func previewIn(name string, over *config.EmailTemplate) PreviewInput {
	return PreviewInput{Template: name, Subject: over.Subject, Body: over.Body}
}

func TestVerifyLinkReturnTo(t *testing.T) {
	s := newSvc(&capture{}, "", nil)
	if got := s.verifyLink("tok/1+2", ""); got != "https://app.example.com/verify-email#token=tok%2F1%2B2" {
		t.Fatalf("no return_to: %s", got)
	}
	got := s.verifyLink("tok/1+2", "https://chat.example.com/a?b=1&c=2#/x")
	want := "https://app.example.com/verify-email?return_to=https%3A%2F%2Fchat.example.com%2Fa%3Fb%3D1%26c%3D2%23%2Fx#token=tok%2F1%2B2"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
