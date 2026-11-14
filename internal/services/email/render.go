package email

import (
	"fmt"
	"html"
	"regexp"
	"strings"

	"github.com/boson-chat/auth/config"
)

// Vars are the values of the template variables {{network}} {{username}}
// {{link}} {{expires}} {{inviter}}.
type Vars struct {
	Network  string
	Username string
	Link     string
	Expires  string
	Inviter  string
}

func (v Vars) get(name string) string {
	var s string
	switch name {
	case "network":
		s = v.Network
	case "username":
		s = v.Username
	case "link":
		s = v.Link
	case "expires":
		s = v.Expires
	case "inviter":
		s = v.Inviter
	}
	// Values are single-line; never let one break a subject header or a
	// paragraph.
	return strings.Join(strings.Fields(s), " ")
}

// Rendered is one email.
type Rendered struct {
	Subject string `json:"subject"`
	HTML    string `json:"html"`
	Text    string `json:"text"`
	// From is the From: header (previews only).
	From string `json:"from"`
	// Warnings are about custom HTML (unknown placeholders and the like;
	// previews only, always a list there).
	Warnings []string `json:"warnings"`
}

// template describes one email kind.
type template struct {
	name    string // config.Email* name
	legacy  string // templates/<legacy>.{txt,html}
	purpose string // metrics
	subject string // default subject
	body    string // default body (plain text with variables)
	button  string // label of the action link when it stands alone in a paragraph
}

var catalog = map[string]template{
	config.EmailVerification: {
		name: config.EmailVerification, legacy: "verify", purpose: PurposeVerify,
		subject: "Verify your email for {{network}}",
		body: "Hi {{username}},\n\nConfirm this email address for your {{network}} account by opening:\n\n{{link}}\n\n" +
			"The link expires in {{expires}} and can be used once. If you didn't create an account, ignore this email.",
		button: "Verify email",
	},
	config.EmailPasswordReset: {
		name: config.EmailPasswordReset, legacy: "reset", purpose: PurposeReset,
		subject: "Reset your {{network}} password",
		body: "Hi {{username}},\n\nSomeone asked to reset the password for your {{network}} account. To choose a new password, open:\n\n{{link}}\n\n" +
			"The link expires in {{expires}} and can be used once. Resetting signs you out everywhere. " +
			"If this wasn't you, ignore this email; your password has not changed.",
		button: "Choose a new password",
	},
	config.EmailAccountSetup: {
		name: config.EmailAccountSetup, legacy: "setup", purpose: PurposeSetup,
		subject: "Your {{network}} account",
		body: "Hi {{username}},\n\nAn administrator created a {{network}} account for you with the username {{username}}. " +
			"To choose your password, open:\n\n{{link}}\n\n" +
			"The link expires in {{expires}} and can be used once. If you weren't expecting this, you can ignore this email.",
		button: "Choose your password",
	},
	config.EmailInvite: {
		name: config.EmailInvite, purpose: PurposeInvite,
		subject: "{{inviter}} invited you to {{network}}",
		body: "Hi,\n\n{{inviter}} invited you to join {{network}}. To create your account, open:\n\n{{link}}\n\n" +
			"The invite expires in {{expires}}. If you weren't expecting this, you can ignore this email.",
		button: "Accept the invite",
	},
}

// varRe matches a known variable; anything else in braces stays literal.
var varRe = regexp.MustCompile(`\{\{\s*(network|username|link|expires|inviter)\s*\}\}`)

// substitute replaces the known variables in s.
func substitute(s string, v Vars) string {
	return varRe.ReplaceAllStringFunc(s, func(m string) string {
		return v.get(varRe.FindStringSubmatch(m)[1])
	})
}

// urlRe finds links to linkify in template text.
var urlRe = regexp.MustCompile(`https?://[^\s<>"'` + "`" + `]+`)

// linkify escapes s and turns http(s) URLs into links.
func linkify(s, accent string) string {
	var b strings.Builder
	last := 0
	for _, loc := range urlRe.FindAllStringIndex(s, -1) {
		start, end := loc[0], loc[1]
		// Sentence punctuation after a URL is not part of it.
		for end > start && strings.ContainsRune(".,;:!?)]}", rune(s[end-1])) {
			end--
		}
		b.WriteString(html.EscapeString(s[last:start]))
		b.WriteString(link(s[start:end], s[start:end], accent))
		last = end
	}
	b.WriteString(html.EscapeString(s[last:]))
	return b.String()
}

func link(href, label, accent string) string {
	return `<a href="` + html.EscapeString(href) + `" style="color:` + safeColor(accent, DefaultAccent) + `;word-break:break-all">` + html.EscapeString(label) + `</a>`
}

// paragraphs splits plain text on blank lines.
var blankLineRe = regexp.MustCompile(`\n[ \t]*\n+`)

func paragraphs(s string) []string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	if s == "" {
		return nil
	}
	parts := blankLineRe.Split(s, -1)
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// bodyBlocks renders the template body: every paragraph a <p>, line
// breaks kept, http(s) URLs in the text linkified, and the action link
// ({{link}} alone in its paragraph) a button row. Template text and
// variable values are both escaped, so the result contains no HTML from
// either. Consecutive paragraphs share one row.
func bodyBlocks(body string, v Vars, label, accent string) []block {
	var out []block
	var run strings.Builder
	flush := func() {
		if run.Len() > 0 {
			out = append(out, block{html: safeHTML(run.String())})
			run.Reset()
		}
	}
	for _, p := range paragraphs(body) {
		if m := varRe.FindStringSubmatch(p); m != nil && m[0] == p && m[1] == "link" && isHTTP(v.get("link")) {
			flush()
			out = append(out, block{button: true, href: v.get("link"), label: label})
			continue
		}
		run.WriteString(`<p style="margin:0 0 16px 0">`)
		last := 0
		for _, loc := range varRe.FindAllStringSubmatchIndex(p, -1) {
			run.WriteString(textHTML(p[last:loc[0]], accent))
			name := p[loc[2]:loc[3]]
			if val := v.get(name); name == "link" && isHTTP(val) {
				run.WriteString(link(val, val, accent))
			} else {
				run.WriteString(html.EscapeString(val))
			}
			last = loc[1]
		}
		run.WriteString(textHTML(p[last:], accent))
		run.WriteString("</p>\n")
	}
	flush()
	return out
}

// textHTML is linkify with line breaks.
func textHTML(s, accent string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = linkify(l, accent)
	}
	return strings.Join(lines, "<br>\n")
}

// DefaultAccent is the button colour of Boson's built-in emails.
const DefaultAccent = "#3b5bdb"

// Logo is the branding logo for emails: URL "" = none; Width and Height
// are its pixel size (0 when unknown, e.g. SVG).
type Logo struct {
	URL           string
	Width, Height int
}

// Logo box in the header: at most 40 px high and 240 px wide.
const (
	logoMaxHeight = 40
	logoMaxWidth  = 240
)

// headerHTML is the logo, or the sender name as text.
func headerHTML(logo Logo, name string) safeHTML {
	if !isHTTP(logo.URL) {
		return safeHTML(`<span style="font-size:18px;font-weight:700;line-height:1.3;color:` + lightPalette.Heading + `">` + html.EscapeString(name) + `</span>`)
	}
	img := `<img src="` + html.EscapeString(logo.URL) + `" alt="` + html.EscapeString(name) + `"`
	if logo.Width > 0 && logo.Height > 0 {
		// Explicit width and height: Outlook ignores CSS sizes on images.
		w, h := logo.Width*logoMaxHeight/logo.Height, logoMaxHeight
		if w > logoMaxWidth {
			w, h = logoMaxWidth, max(1, logo.Height*logoMaxWidth/logo.Width)
		}
		w = max(w, 1)
		img += fmt.Sprintf(` width="%d" height="%d" style="display:block;width:%dpx;height:%dpx;max-width:100%%;border:0;outline:none;text-decoration:none">`, w, h, w, h)
	} else {
		img += fmt.Sprintf(` height="%d" style="display:block;height:%dpx;width:auto;max-width:%dpx;border:0;outline:none;text-decoration:none">`, logoMaxHeight, logoMaxHeight, logoMaxWidth)
	}
	return safeHTML(img)
}

// previewLine is the inbox preview: the start of the text without the
// action link (it is the button), one line.
func previewLine(body string, v Vars) string {
	var parts []string
	for _, p := range paragraphs(body) {
		if m := varRe.FindStringSubmatch(p); m != nil && m[0] == p && m[1] == "link" {
			continue
		}
		parts = append(parts, substitute(p, v))
	}
	s := strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
	if r := []rune(s); len(r) > 140 {
		s = strings.TrimSpace(string(r[:139])) + "…"
	}
	return s
}

// branded renders tpl (with overrides from cfg and over) into the branded
// MJML layout. logo.URL "" = the sender name as text.
func branded(tpl template, cfg *config.EmailConfig, over *config.EmailTemplate, v Vars, logo Logo, cu custom) (Rendered, error) {
	sks, err := layouts()
	if err != nil {
		return Rendered{}, err
	}
	subject, body, bodySet := tpl.subject, tpl.body, false
	if cfg != nil {
		if t, ok := cfg.Templates[tpl.name]; ok {
			if t.Subject != nil {
				subject = *t.Subject
			}
			if t.Body != nil {
				body, bodySet = *t.Body, true
			}
		}
	}
	if over != nil {
		if over.Subject != nil {
			subject = *over.Subject
		}
		if over.Body != nil {
			body, bodySet = *over.Body, true
		}
	}
	accent, name, footer := DefaultAccent, v.get("network"), ""
	if cfg != nil {
		if cfg.Accent != "" {
			accent = cfg.Accent
		}
		if cfg.SenderName != "" {
			name = cfg.SenderName
		}
		footer = substitute(cfg.Footer, v)
		if !cfg.Logo {
			logo = Logo{}
		}
	}
	accent = safeColor(accent, DefaultAccent)
	r := Rendered{Subject: strings.Join(strings.Fields(substitute(subject, v)), " ")}
	// Plain-text part: the body with the variables filled in.
	text := strings.Join(paragraphs(substitute(body, v)), "\n\n") + "\n"
	r.Text = text
	if footer != "" {
		r.Text += "\n-- \n" + footer + "\n"
	}
	if !cu.empty() {
		vals := docValues{
			text: map[string]string{"subject": r.Subject, "network": v.get("network"), "username": v.get("username"),
				"inviter": v.get("inviter"), "expires": v.get("expires"), "footer": footer, "sender_name": name},
			link: v.get("link"), logoURL: logo.URL, accent: accent,
		}
		if d := cu.tpl; d != nil {
			// The whole email is the admin's; the text part is the body when
			// one is set, else the HTML's text.
			r.HTML = d.fill(vals)
			if !bodySet {
				r.Text = htmlText(r.HTML)
			}
			r.Warnings = append([]string(nil), d.warnings...)
			return r, nil
		}
		vals.content = contentHTML(bodyBlocks(body, v, tpl.button, accent), accent)
		r.HTML = cu.layout.fill(vals)
		r.Warnings = append([]string(nil), cu.layout.warnings...)
		return r, nil
	}
	p := page{
		title: r.Subject, preview: previewLine(body, v), header: headerHTML(logo, name),
		blocks: bodyBlocks(body, v, tpl.button, accent), accent: accent, onAccent: onAccent(accent),
	}
	sk := sks[0]
	if footer != "" {
		sk, p.footer = sks[1], safeHTML(textHTML(footer, accent))
	}
	r.HTML = sk.fill(p)
	return r, nil
}
