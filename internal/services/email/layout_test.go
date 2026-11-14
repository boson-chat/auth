package email

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/boson-chat/auth/config"
)

var update = flag.Bool("update", false, "rewrite testdata/branded golden files")

const goldenLogo = "https://auth.example.com/v1/branding/assets/wordmark-91bc.png?v=1f2e3d4c5b6a7980"

// brandedCases are the golden branded emails: every template with the full
// branding, and the bare variant (no logo, no footer, default accent).
func brandedCases() map[string]*config.EmailConfig {
	full := &config.EmailConfig{SenderName: "Example Chat", Accent: "#7c3aed", Footer: "Example Chat · https://example.com\nYou get this because you have an account.", Logo: true}
	out := map[string]*config.EmailConfig{}
	for _, name := range config.EmailTemplates {
		out[name] = full
	}
	out["verification-bare"] = &config.EmailConfig{}
	return out
}

func goldenSvc() *EmailService {
	s := newSvc(&capture{}, "", nil)
	s.opts.Logo = func() Logo { return Logo{URL: goldenLogo, Width: 480, Height: 120} }
	return s
}

// The branded MJML layout, byte for byte (go test -run Golden -update
// after an intended change to layout.mjml, then look at the samples).
func TestBrandedGolden(t *testing.T) {
	s := goldenSvc()
	for name, cfg := range brandedCases() {
		s.SetConfig(cfg)
		tpl, _, _ := strings.Cut(name, "-")
		r, err := s.Preview(context.Background(), "alice", PreviewInput{Template: tpl})
		if err != nil {
			t.Fatal(err)
		}
		for ext, got := range map[string]string{"subject": r.Subject, "txt": r.Text, "html": r.HTML} {
			path := filepath.Join("testdata", "branded", name+"."+ext)
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("%s differs (go test -run Golden -update)\n got %q\nwant %q", path, got, want)
			}
		}
	}
}

// EMAIL_SAMPLES_DIR=/some/dir go test -run WriteSamples writes the golden
// cases as .html files to look at in a browser.
func TestWriteSamples(t *testing.T) {
	dir := os.Getenv("EMAIL_SAMPLES_DIR")
	if dir == "" {
		t.Skip("EMAIL_SAMPLES_DIR not set")
	}
	s := goldenSvc()
	for name, cfg := range brandedCases() {
		s.SetConfig(cfg)
		tpl, _, _ := strings.Cut(name, "-")
		r, err := s.Preview(context.Background(), "alice", PreviewInput{Template: tpl})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".html"), []byte(r.HTML), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLayoutStructure(t *testing.T) {
	s := goldenSvc()
	s.SetConfig(brandedCases()[config.EmailVerification])
	r, err := s.Preview(context.Background(), "alice", PreviewInput{Template: config.EmailVerification})
	if err != nil {
		t.Fatal(err)
	}
	h := r.HTML
	for _, want := range []string{
		`<!doctype html>`,
		`<html lang="en" dir="ltr"`,
		`<title>Verify your email for Example &lt;Net&gt; &amp; Co</title>`,
		`<meta name="color-scheme" content="light dark">`,
		`@media (prefers-color-scheme: dark)`,
		`max-width:600px`,
		`<!--[if mso | IE]>`, // Outlook tables survive (comments are not stripped)
		// Logo: 480×120 scaled to the 40 px box, with explicit width/height for Outlook.
		`<img src="` + strings.ReplaceAll(goldenLogo, "&", "&amp;") + `" alt="Example Chat" width="160" height="40"`,
		`bgcolor="#7c3aed"`,
		`color:#ffffff`,
		// Inbox preview line.
		`>Hi alice, Confirm this email address for your Example &lt;Net&gt; &amp; Co account by opening: The link expires in 24 hours`,
		`Example Chat · <a href="https://example.com" style="color:#7c3aed;word-break:break-all">https://example.com</a><br>`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
	if regexp.MustCompile(`BXSLOT_|#0b05e|<!--bx:`).MatchString(h) {
		t.Fatal("placeholders left in the HTML")
	}
	if strings.Contains(h, "fonts.googleapis.com") {
		t.Fatal("no web fonts: system font stack only")
	}
	// No footer → the footer row is gone entirely.
	s.SetConfig(&config.EmailConfig{})
	r, _ = s.Preview(context.Background(), "alice", PreviewInput{Template: config.EmailVerification})
	if strings.Contains(r.HTML, "bx-foot\"") || strings.Contains(r.HTML, "<img") {
		t.Fatal("bare variant has a footer or logo")
	}
}

// Every value that reaches the HTML is escaped by the slot it fills; none
// of them can add markup or break out of an attribute.
func TestLayoutEscapesEverySlot(t *testing.T) {
	s := newSvc(&capture{}, "", nil)
	s.opts.Logo = func() Logo { return Logo{URL: `https://x.example/l.png?a=1&b="><script>`, Width: 10, Height: 10} }
	s.SetSiteName(`Net</title><script>alert(1)</script>`)
	sub := `{{network}} "quoted" </title>`
	body := "<img src=x onerror=alert(1)>\n\n{{link}}\n\njavascript:alert(1) and https://ok.example/?q=<b>"
	s.SetConfig(&config.EmailConfig{
		SenderName: `"><svg onload=alert(1)>`, Footer: `<b>bold</b> javascript:alert(2)`, Logo: true,
		Templates: map[string]config.EmailTemplate{config.EmailVerification: {Subject: &sub, Body: &body}},
	})
	r, err := s.Preview(context.Background(), `<u>admin</u>`, PreviewInput{Template: config.EmailVerification})
	if err != nil {
		t.Fatal(err)
	}
	h := r.HTML
	for _, bad := range []string{"<script>", "<svg", "<img src=x", "<b>", "<u>", `href="javascript`} {
		if strings.Contains(h, bad) {
			t.Errorf("HTML contains %q", bad)
		}
	}
	for _, want := range []string{
		`<title>Net&lt;/title&gt;&lt;script&gt;alert(1)&lt;/script&gt; &#34;quoted&#34; &lt;/title&gt;</title>`,
		`alt="&#34;&gt;&lt;svg onload=alert(1)&gt;"`,
		`src="https://x.example/l.png?a=1&amp;b=&#34;&gt;&lt;script&gt;"`,
		`&lt;img src=x onerror=alert(1)&gt;`,
		`javascript:alert(1) and <a href="https://ok.example/?q=" `, // only http(s) is linkified; < ends the URL
		`&lt;b&gt;bold&lt;/b&gt; javascript:alert(2)`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
}

func TestButtonRule(t *testing.T) {
	v := Vars{Link: "https://app.example.com/x#token=a&b"}
	bl := bodyBlocks("Hi\n\nline one\nline two\n\n  {{ link }}  \n\nSee {{link}}.\n\nbye", v, "Go", "#123456")
	if len(bl) != 3 || bl[0].button || !bl[1].button || bl[2].button {
		t.Fatalf("%+v", bl)
	}
	if bl[1].href != v.Link || bl[1].label != "Go" {
		t.Fatalf("%+v", bl[1])
	}
	if strings.Count(string(bl[0].html), "<p ") != 2 || !strings.Contains(string(bl[0].html), "line one<br>\nline two") {
		t.Fatal(bl[0].html)
	}
	if !strings.Contains(string(bl[2].html), `See <a href="https://app.example.com/x#token=a&amp;b" style="color:#123456;word-break:break-all">`) {
		t.Fatal(bl[2].html)
	}
	// A paragraph that is the link plus text is not a button; a non-http
	// link is never a button or a link.
	bl = bodyBlocks("{{link}} now\n\n{{link}}", Vars{Link: "javascript:alert(1)"}, "Go", "#123456")
	if len(bl) != 1 || bl[0].button || strings.Contains(string(bl[0].html), "<a") {
		t.Fatalf("%+v", bl)
	}
	// No link at all: the paragraph stays (empty).
	bl = bodyBlocks("{{link}}", Vars{}, "Go", "#123456")
	if len(bl) != 1 || bl[0].button {
		t.Fatalf("%+v", bl)
	}
}

func TestSkeletonFillGuards(t *testing.T) {
	sks, err := layouts()
	if err != nil {
		t.Fatal(err)
	}
	h := sks[0].fill(page{accent: "red;background:url(x)", onAccent: "#FFF", blocks: []block{{button: true, href: "javascript:alert(1)", label: "<x>"}}})
	if strings.Contains(h, "red;") || strings.Contains(h, "javascript:") || strings.Contains(h, "<x>") {
		t.Fatal("fill must sanitise colours and URLs and escape labels")
	}
	if !strings.Contains(h, `href="#"`) || !strings.Contains(h, "bgcolor=\""+DefaultAccent+"\"") {
		t.Fatal("fallbacks")
	}
	if _, err := parseSkeleton("<html>no markers</html>", false); err == nil {
		t.Fatal("markers are required")
	}
	if _, err := parseSkeleton("BXSLOT_TITLE BXSLOT_PREVIEW BXSLOT_HEADER #0b05e1<!--bx:para-->BXSLOT_HREF<!--bx:button--><!--bx:end-->", false); err == nil {
		t.Fatal("a slot outside its region is an error")
	}
}

func TestOnAccent(t *testing.T) {
	for accent, want := range map[string]string{
		"#3b5bdb": "#ffffff", "#7c3aed": "#ffffff", "#000000": "#ffffff",
		"#ffff00": "#111118", "#ffffff": "#111118", "#7dd3fc": "#111118", "bad": "#ffffff",
	} {
		if got := onAccent(accent); got != want {
			t.Errorf("onAccent(%s) = %s, want %s", accent, got, want)
		}
	}
}

func TestHeaderLogoSizing(t *testing.T) {
	for _, c := range []struct {
		logo Logo
		want string
	}{
		{Logo{URL: "https://x/l.png", Width: 100, Height: 100}, `width="40" height="40"`},
		{Logo{URL: "https://x/l.png", Width: 2000, Height: 100}, `width="240" height="12"`},
		{Logo{URL: "https://x/l.png", Width: 10, Height: 4000}, `width="1" height="40"`},
		{Logo{URL: "https://x/l.svg"}, `height="40" style="display:block;height:40px;width:auto;max-width:240px`},
		{Logo{URL: "data:image/png;base64,AAAA"}, `<span `}, // only http(s) images
	} {
		if got := string(headerHTML(c.logo, "N")); !strings.Contains(got, c.want) {
			t.Errorf("%+v: %s", c.logo, got)
		}
	}
}
