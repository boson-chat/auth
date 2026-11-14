package email

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nethtml "golang.org/x/net/html"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/configfile"
)

// hostile values for every text placeholder.
const (
	evilUser = `"><script>alert(1)</script>' onmouseover=alert(2) javascript:alert(3) }</style><style>body{x:y}`
	evilNet  = `Net</title><img src=x onerror=alert(4)>;background:url(http://evil.example/)`
)

func evilVals(link, logo string) docValues {
	text := map[string]string{}
	for name, k := range placeholders {
		if k == phText {
			text[name] = evilUser
		}
	}
	text["network"] = evilNet
	return docValues{text: text, link: link, logoURL: logo, accent: "#7c3aed", content: "<p>CONTENT</p>"}
}

func mustDoc(t *testing.T, src string, layout bool) *customDoc {
	t.Helper()
	d, err := compileDoc(src, layout)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Every placeholder in every HTML context gets that context's escaping.
func TestCustomEscapingEveryContext(t *testing.T) {
	src := `<!doctype html><html><head><title>{{subject}} {{network}}</title>
<style>.a{color:{{accent}};font-family:{{username}};background:url('{{logo_url}}')} .b{x:{{link}}}</style>
<script>var u="{{username}}", l="{{link}}", c="{{accent}}";</script>
<!--[if mso]><table bgcolor="{{accent}}" title="{{username}}"><tr><td>{{network}}</td></tr></table><![endif]-->
<!-- note {{username}} -->
</head><body>
<p class="t">{{username}}</p>
<a href="{{link}}" title="{{username}}" data-x={{username}}>{{link}}</a>
<a class="tx" href="{{username}}">x</a>
<a class="q" href="https://r.example/?u={{username}}&next={{link}}">y</a>
<img src="{{logo_url}}" alt="{{sender_name}}" style="color:{{accent}};font:{{username}};background:url({{logo_url}})" onclick="go('{{username}}')">
<div {{username}} class="tag">{{content}}</div>
<p>{{footer}}</p>
</body></html>`
	d := mustDoc(t, src, true)
	out := d.fill(evilVals("https://app.example.com/v#token=a&b", `https://cdn.example/l.png?a=1&b='x'"y"(z)`))

	for _, want := range []string{
		// <title>: HTML-escaped (quotes too).
		`<title>&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&#39; onmouseover=alert(2) javascript:alert(3) }&lt;/style&gt;&lt;style&gt;body{x:y} Net&lt;/title&gt;&lt;img src=x onerror=alert(4)&gt;;background:url(http://evil.example/)</title>`,
		// <style>: colours as they are, text reduced, URLs percent-encoded.
		`.a{color:#7c3aed;font-family:scriptalert1script onmouseoveralert2 javascriptalert3 stylestylebodyxy;background:url('https://cdn.example/l.png?a=1&b=%27x%27%22y%22%28z%29')} .b{x:https://app.example.com/v#token=a&b}`,
		// <script>: only the colour.
		`var u="", l="", c="#7c3aed";`,
		// Conditional comments are markup.
		`<table bgcolor="#7c3aed" title="&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&#39; onmouseover=alert(2) javascript:alert(3) }&lt;/style&gt;&lt;style&gt;body{x:y}">`,
		// Body text.
		`<p class="t">&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&#39; onmouseover=alert(2)`,
		// URL attribute: the link as it is, attribute-escaped.
		`<a href="https://app.example.com/v#token=a&amp;b" title="&#34;&gt;&lt;script&gt;`,
		// Unquoted attribute: nothing that ends the value.
		`data-x=&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&#39;&#32;onmouseover&#61;alert(2)&#32;javascript:alert(3)&#32;}&lt;/style&gt;&lt;style&gt;body{x:y}>`,
		// Text as a URL: percent-encoded, so no scheme.
		`<a class="tx" href="%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E%27+onmouseover%3Dalert%282%29+javascript%3Aalert%283%29+%7D%3C%2Fstyle%3E%3Cstyle%3Ebody%7Bx%3Ay%7D">`,
		// Inside a URL: query-escaped, the link too.
		`href="https://r.example/?u=%22%3E%3Cscript%3E`,
		`&next=https%3A%2F%2Fapp.example.com%2Fv%23token%3Da%26b">`,
		// Image URL and alt.
		`<img src="https://cdn.example/l.png?a=1&amp;b=&#39;x&#39;&#34;y&#34;(z)" alt="&#34;&gt;&lt;script&gt;`,
		// style attribute.
		`style="color:#7c3aed;font:scriptalert1script onmouseoveralert2 javascriptalert3 stylestylebodyxy;background:url(https://cdn.example/l.png?a=1&amp;b=%27x%27%22y%22%28z%29)"`,
		// on* attribute and a tag position: left out.
		`onclick="go('')"`, `<div  class="tag"><p>CONTENT</p></div>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks\n%s", want)
		}
	}
	// Structurally: the only script element and on* attribute are the
	// document's own, every URL is http(s), # or relative without a scheme.
	root, err := nethtml.Parse(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	scripts, ons := 0, 0
	var walk func(n *nethtml.Node)
	walk = func(n *nethtml.Node) {
		if n.Type == nethtml.ElementNode {
			if n.Data == "script" {
				scripts++
			}
			for _, a := range n.Attr {
				if strings.HasPrefix(a.Key, "on") {
					ons++
				}
				if (a.Key == "href" || a.Key == "src") && strings.Contains(strings.SplitN(a.Val, "/", 2)[0], ":") && !isHTTP(a.Val) {
					t.Errorf("%s=%q has a scheme", a.Key, a.Val)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	if scripts != 1 || ons != 1 {
		t.Errorf("scripts %d, on* attributes %d: placeholders added markup", scripts, ons)
	}
	if len(d.warnings) != 6 { // script ×3, CSS text ×2, tag position
		t.Errorf("warnings %q", d.warnings)
	}
}

// Non-http(s) URLs never reach the document.
func TestCustomURLsMustBeHTTP(t *testing.T) {
	d := mustDoc(t, `<a href="{{link}}">{{link}}</a><img src="{{logo_url}}">`, false)
	out := d.fill(evilVals("javascript:alert(1)", "data:text/html,x"))
	if out != `<a href="#">#</a><img src="">` {
		t.Fatal(out)
	}
	// An invalid accent falls back to Boson's.
	d = mustDoc(t, `<a href="{{link}}" style="color:{{accent}}">x</a>`, false)
	v := evilVals("https://x.example/", "")
	v.accent = "red;background:url(x)"
	if out := d.fill(v); out != `<a href="https://x.example/" style="color:`+DefaultAccent+`">x</a>` {
		t.Fatal(out)
	}
}

// One pass: substituted values are never scanned for placeholders.
func TestCustomSinglePass(t *testing.T) {
	d := mustDoc(t, `<title>{{subject}}</title><p>{{username}}</p><div>{{content}}</div><a href="{{link}}">{{network}}</a>`, true)
	v := docValues{text: map[string]string{"subject": "{{content}}", "username": "{{ link }}", "network": "{{accent}}"},
		link: "https://x.example/{{username}}", accent: "#112233", content: "<p>{{username}} BODY</p>"}
	out := d.fill(v)
	want := `<title>{{content}}</title><p>{{ link }}</p><div><p>{{username}} BODY</p></div><a href="https://x.example/{{username}}">{{accent}}</a>`
	if out != want {
		t.Fatalf("\n got %s\nwant %s", out, want)
	}
}

func TestCustomValidation(t *testing.T) {
	for _, c := range []struct {
		src    string
		layout bool
		err    string
	}{
		{`<p>hi</p>`, true, "must contain {{content}}"},
		{"<p>{{content}}</p>\n<p>{{ content }}</p>", true, "exactly once, found 2 (line 1, column 4; line 2, column 4)"},
		{`<div title="{{content}}">x</div>`, true, "{{content}} at line 1, column 13 must be in the body text, not in an attribute"},
		{`<title>{{content}}</title>`, true, "not in a title"},
		{`<!-- {{content}} -->`, true, "not in a comment"},
		{`<style>{{content}}</style>`, true, "not in CSS"},
		{`<div {{content}}>`, true, "not in a tag"},
		{`<p>no link</p>`, false, "must contain {{link}}"},
		{`<a {{link}}>x</a>`, false, "must contain {{link}}"},
		{`<script>{{link}}</script>`, false, "must contain {{link}}"},
		{strings.Repeat("x", config.MaxEmailFileBytes+1) + "{{content}}", true, "must be at most 512 KB"},
	} {
		_, err := compileDoc(c.src, c.layout)
		if err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%.60q: %v, want %q", c.src, err, c.err)
		}
	}
	// Exactly at the limit is fine.
	big := "{{content}}" + strings.Repeat("x", config.MaxEmailFileBytes-len("{{content}}"))
	if _, err := compileDoc(big, true); err != nil {
		t.Fatal(err)
	}
	// Unknown placeholders and {{content}} in a whole email stay literal
	// and warn; spaces inside the braces are allowed.
	d := mustDoc(t, "<p>{{ username }} {{unknown}}\n{{content}}</p><a href=\"{{link}}\">x</a>", false)
	out := d.fill(docValues{text: map[string]string{"username": "al"}, link: "https://x.example/"})
	if out != "<p>al {{unknown}}\n{{content}}</p><a href=\"https://x.example/\">x</a>" {
		t.Fatal(out)
	}
	if len(d.warnings) != 2 || !strings.Contains(d.warnings[0], "unknown placeholder {{unknown}} at line 1, column 19") ||
		!strings.Contains(d.warnings[1], "{{content}} at line 2, column 1 is only for the layout") {
		t.Fatalf("%q", d.warnings)
	}
}

func TestHTMLText(t *testing.T) {
	doc := `<!doctype html><html><head><title>T</title><style>p{x:y}</style></head><body>
<div style="display:none;max-height:0px">preview line</div>
<!--[if mso]><p>outlook only</p><![endif]-->
<table><tr><td><h1>Hello  <b>alice</b></h1>
<p>Open <a href="https://x.example/a">this link</a> or
<a href="https://x.example/b">https://x.example/b</a>.<br>Second line</p>
<table><tr><td><a href="https://x.example/c"><img src="https://x.example/i.png" alt="logo"></a></td></tr></table>
<p><a href="mailto:a@example.com">mail us</a></p>
<script>var x = 1;</script>
</td></tr></table>
<p>Footer &amp; co</p></body></html>`
	want := "Hello alice\n\nOpen this link (https://x.example/a) or https://x.example/b.\nSecond line\n\nhttps://x.example/c\n\nmail us\n\nFooter & co\n"
	if got := htmlText(doc); got != want {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
	if htmlText("<html></html>") != "" {
		t.Fatal("empty")
	}
}

// writeEmails writes files into a fresh emails directory.
func writeEmails(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadFiles(t *testing.T) {
	layout := `<html><body>{{content}}</body></html>`
	invite := `<html><body><a href="{{link}}">Join {{network}}</a> {{nope}}</body></html>`
	dir := writeEmails(t, map[string]string{"layout-1.html": layout, "layout-1.mjml": "<mjml/>", "invite-1.html": invite})
	cfg := func() *config.EmailConfig {
		return &config.EmailConfig{
			Layout: &config.EmailFiles{Key: "auth.email.layout", MJML: "layout-1.mjml", HTML: "layout-1.html", Line: 5, Column: 13, MJMLLine: 4, MJMLColumn: 13},
			Templates: map[string]config.EmailTemplate{config.EmailInvite: {Files: &config.EmailFiles{
				Key: "auth.email.templates.invite", HTML: "invite-1.html", Line: 9, Column: 15}}},
		}
	}
	c := cfg()
	warnings, err := LoadFiles(c, dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Layout.Source != layout || c.Templates[config.EmailInvite].Files.Source != invite {
		t.Fatal("sources not loaded")
	}
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "auth.email.templates.invite.html: invite-1.html: unknown placeholder {{nope}}") {
		t.Fatalf("%q", warnings)
	}
	if w, err := LoadFiles(nil, "/nonexistent"); w != nil || err != nil {
		t.Fatal("nil config: nothing to read")
	}
	if w, err := LoadFiles(&config.EmailConfig{}, "/nonexistent"); w != nil || err != nil {
		t.Fatal("no files: the directory isn't needed")
	}

	if err := os.Symlink(filepath.Join(t.TempDir(), "outside.html"), filepath.Join(dir, "link.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub.html"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "big.html"), []byte("{{content}}"+strings.Repeat("x", config.MaxEmailFileBytes)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nocontent.html"), []byte("<p>x</p>"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		edit      func(c *config.EmailConfig)
		dir       string
		line, col int
		msg       string
	}{
		{func(c *config.EmailConfig) { c.Layout.HTML = "gone.html" }, dir, 5, 13, "auth.email.layout.html: gone.html not found in " + dir},
		{func(c *config.EmailConfig) { c.Layout.MJML = "gone.mjml" }, dir, 4, 13, "auth.email.layout.mjml: gone.mjml not found"},
		{func(c *config.EmailConfig) { c.Layout.HTML = "link.html" }, dir, 5, 13, "auth.email.layout.html: link.html"},
		{func(c *config.EmailConfig) { c.Layout.HTML = "sub.html" }, dir, 5, 13, "not a regular file"},
		{func(c *config.EmailConfig) { c.Layout.HTML = "big.html" }, dir, 5, 13, "big.html is larger than 512 KB"},
		{func(c *config.EmailConfig) { c.Layout.HTML = "nocontent.html" }, dir, 5, 13, "auth.email.layout.html: nocontent.html must contain {{content}}"},
		{func(c *config.EmailConfig) { c.Layout.HTML = "invite-1.html" }, dir, 5, 13, "must contain {{content}}"},
		{func(c *config.EmailConfig) { c.Templates[config.EmailInvite].Files.HTML = "layout-1.html" }, dir, 9, 15, "auth.email.templates.invite.html: layout-1.html must contain {{link}}"},
		{func(c *config.EmailConfig) {}, filepath.Join(dir, "missing"), 5, 13, "can't open the emails directory"},
	} {
		c := cfg()
		tc.edit(c)
		_, err := LoadFiles(c, tc.dir)
		var ce *configfile.Error
		if !errors.As(err, &ce) || ce.Line != tc.line || ce.Column != tc.col || !strings.Contains(ce.Msg, tc.msg) {
			t.Errorf("%v, want line %d col %d %q", err, tc.line, tc.col, tc.msg)
		}
	}
}

func defaultCompiled(t *testing.T, part string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(DefaultMJMLTestdata, part+".html"))
	if err != nil {
		t.Fatal(err, "(go generate ./internal/services/email)")
	}
	return string(b)
}

// A saved custom layout and whole-email override are used for real sends,
// with the plain-text part as the contract says.
func TestCustomHTMLSends(t *testing.T) {
	m := &capture{}
	s := newSvc(m, "https://auth.example.com/logo.png", nil)
	body := "Hi {{username}}, reset here:\n\n{{link}}"
	s.SetConfig(&config.EmailConfig{SenderName: "Example Chat", Accent: "#7c3aed", Footer: "Example footer", Logo: true,
		Layout: &config.EmailFiles{Key: "auth.email.layout", HTML: "l.html", Source: defaultCompiled(t, "layout")},
		Templates: map[string]config.EmailTemplate{
			config.EmailAccountSetup:  {Files: &config.EmailFiles{HTML: "s.html", Source: defaultCompiled(t, config.EmailAccountSetup)}},
			config.EmailPasswordReset: {Body: &body, Files: &config.EmailFiles{HTML: "r.html", Source: `<p>Reset: <a href="{{link}}">go</a></p>`}},
		}})
	sendAll(s)

	v := m.bySubject("Verify")
	for _, want := range []string{"<title>Verify your email for Example &lt;Net&gt; &amp; Co</title>", ">Example Chat</div>",
		`<p style="margin:0 0 16px 0">Hi alice&lt;b&gt;,</p>`, `bgcolor="#7c3aed"`, `href="https://app.example.com/verify-email#token=tok%2F1%2B2"`,
		">Verify email</a>", "Example footer", "border-top:4px solid #7c3aed"} {
		if !strings.Contains(v.HTML, want) {
			t.Errorf("layout email lacks %q", want)
		}
	}
	if !strings.HasPrefix(v.Text, "Hi alice<b>,\n\n") || !strings.HasSuffix(v.Text, "\n-- \nExample footer\n") {
		t.Errorf("layout text %q", v.Text)
	}

	// Whole email from the default MJML, no body: text from the HTML.
	st := m.bySubject("Your")
	if !strings.Contains(st.HTML, `href="https://app.example.com/reset-password#token=tok%2F1%2B2"`) || !strings.Contains(st.HTML, "Hi alice&lt;b&gt;,") {
		t.Errorf("override HTML %s", st.HTML)
	}
	wantText := "Example Chat\n\nHi alice<b>,\n\nAn administrator created a Example <Net> & Co account for you with the username alice<b>. To choose your password, open:\n\n" +
		"Choose your password (https://app.example.com/reset-password#token=tok%2F1%2B2)\n\n" +
		"The link expires in 3 days and can be used once. If you weren't expecting this, you can ignore this email.\n\nExample footer\n"
	if st.Text != wantText {
		t.Errorf("override text\n got %q\nwant %q", st.Text, wantText)
	}
	// Whole email with a body: the body is the text.
	r := m.bySubject("Reset")
	if r.HTML != `<p>Reset: <a href="https://app.example.com/reset-password#token=tok%2F1%2B2">go</a></p>` ||
		r.Text != "Hi alice<b>, reset here:\n\nhttps://app.example.com/reset-password#token=tok%2F1%2B2\n\n-- \nExample footer\n" {
		t.Errorf("%+v", r)
	}
}

func TestPreviewUnsavedHTML(t *testing.T) {
	s := newSvc(&capture{}, "https://auth.example.com/logo.png", nil)
	ctx := context.Background()
	layout := defaultCompiled(t, "layout")

	// Nothing saved: the unsaved layout applies (not the built-in email).
	r, err := s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification, LayoutHTML: &layout})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.HTML, ">Verify email</a>") || !strings.Contains(r.HTML, "border-top:4px solid "+DefaultAccent) ||
		r.Warnings == nil || len(r.Warnings) != 0 || !strings.HasPrefix(r.Text, "Hi admin,") {
		t.Fatalf("%+v", r)
	}
	// An unsaved whole email for this template wins over the layout.
	html := `<p>{{ username }} {{bogus}}: <a href="{{link}}">go</a></p>`
	r, err = s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification, LayoutHTML: &layout, HTML: &html})
	if err != nil {
		t.Fatal(err)
	}
	if r.HTML != `<p>admin {{bogus}}: <a href="https://app.example.com/verify-email#token=example-token">go</a></p>` ||
		r.Text != "admin {{bogus}}: go (https://app.example.com/verify-email#token=example-token)\n" ||
		len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "{{bogus}}") {
		t.Fatalf("%+v", r)
	}
	// With an unsaved body, that body is the text.
	r, _ = s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification, HTML: &html, Body: ptr("Typed {{link}}")})
	if r.Text != "Typed https://app.example.com/verify-email#token=example-token\n" {
		t.Fatal(r.Text)
	}

	// Saved files; "" previews without them.
	s.SetConfig(&config.EmailConfig{Layout: &config.EmailFiles{HTML: "l.html", Source: "<div>SAVED {{content}}</div>"},
		Templates: map[string]config.EmailTemplate{config.EmailInvite: {Files: &config.EmailFiles{HTML: "i.html", Source: `<a href="{{link}}">SAVED INVITE</a>`}}}})
	r, _ = s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification})
	if !strings.HasPrefix(r.HTML, "<div>SAVED <p") {
		t.Fatal(r.HTML)
	}
	r, _ = s.Preview(ctx, "admin", PreviewInput{Template: config.EmailInvite})
	if r.HTML != `<a href="https://app.example.com/#invite=inv_example">SAVED INVITE</a>` {
		t.Fatal(r.HTML)
	}
	none := ""
	r, _ = s.Preview(ctx, "admin", PreviewInput{Template: config.EmailInvite, HTML: &none})
	if !strings.HasPrefix(r.HTML, "<div>SAVED <p") {
		t.Fatal("html \"\" → the layout", r.HTML)
	}
	r, _ = s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification, LayoutHTML: &none})
	if !strings.Contains(r.HTML, "<!--bx:") && !strings.Contains(r.HTML, "mj-outlook") {
		t.Fatal("layout_html \"\" → Boson's layout", r.HTML[:200])
	}
	// The unsaved HTML is part of the cache key.
	other := "<b>{{content}}</b>"
	r, _ = s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification, LayoutHTML: &other})
	if !strings.HasPrefix(r.HTML, "<b><p") {
		t.Fatal(r.HTML)
	}

	// Field-tagged 400s.
	big := strings.Repeat("x", config.MaxEmailFileBytes+1)
	for _, c := range []struct {
		in    PreviewInput
		field string
		msg   string
	}{
		{PreviewInput{Template: config.EmailVerification, LayoutHTML: ptr("<p>no content</p>")}, "layout_html", "layout_html must contain {{content}}"},
		{PreviewInput{Template: config.EmailVerification, LayoutHTML: ptr("{{content}}{{content}}")}, "layout_html", "exactly once"},
		{PreviewInput{Template: config.EmailVerification, HTML: ptr("<p>no link</p>")}, "html", "html must contain {{link}}"},
		{PreviewInput{Template: config.EmailVerification, LayoutHTML: &big}, "layout_html", "must be at most 512 KB"},
		{PreviewInput{Template: config.EmailVerification, HTML: &big}, "html", "must be at most 512 KB"},
	} {
		_, err := s.Preview(ctx, "admin", c.in)
		e, ok := apperr.As(err)
		if !ok || e.Status != 400 || e.Field != c.field || !strings.Contains(e.Message, c.msg) {
			t.Errorf("%v, want %s: %s", err, c.field, c.msg)
		}
	}
}

func TestDefaultMJML(t *testing.T) {
	layout, err := DefaultMJML("layout")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(layout, "{{content}}") != 1 || strings.Contains(layout, "BXSLOT") || strings.Contains(layout, "{{link}}") ||
		!strings.HasPrefix(layout, "<mjml") || !strings.Contains(layout, "<mj-title>{{subject}}</mj-title>") {
		t.Fatal(layout)
	}
	for _, name := range config.EmailTemplates {
		src, err := DefaultMJML(name)
		if err != nil {
			t.Fatal(err)
		}
		tpl := catalog[name]
		if strings.Contains(src, "{{content}}") || !strings.Contains(src, `href="{{link}}"`) || !strings.Contains(src, ">"+tpl.button+"</a>") {
			t.Errorf("%s: %s", name, src)
		}
	}
	src, _ := DefaultMJML(config.EmailVerification)
	if !strings.Contains(src, `<p style="margin:0 0 16px 0">Hi {{username}},</p>`) || !strings.Contains(src, "didn't create") {
		t.Error(src)
	}
	_, err = DefaultMJML("nope")
	if e, ok := apperr.As(err); !ok || e.Field != "part" {
		t.Fatal(err)
	}
}
