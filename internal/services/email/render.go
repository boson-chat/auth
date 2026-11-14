package email

import (
	"bytes"
	"fmt"
	"html"
	htmltemplate "html/template"
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
	return `<a href="` + html.EscapeString(href) + `" style="color:` + accent + `;word-break:break-all">` + html.EscapeString(label) + `</a>`
}

func button(href, label, accent string) string {
	return `<a href="` + html.EscapeString(href) + `" style="display:inline-block;padding:.6rem 1.2rem;background:` + accent +
		`;color:#fff;border-radius:6px;text-decoration:none;font-weight:600">` + html.EscapeString(label) + `</a>`
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

// bodyHTML renders the template body: every paragraph a <p>, line breaks
// kept, URLs in the text linkified, the action link ({{link}} alone in its
// paragraph) a button. Template text and variable values are both escaped,
// so the result contains no HTML from either.
func bodyHTML(body string, v Vars, label, accent string) string {
	var b strings.Builder
	for _, p := range paragraphs(body) {
		if m := varRe.FindStringSubmatch(p); m != nil && m[0] == p && m[1] == "link" && v.Link != "" {
			b.WriteString(`<p style="margin:1.4em 0">` + button(v.get("link"), label, accent) + "</p>\n")
			continue
		}
		b.WriteString(`<p style="margin:0 0 1em 0">`)
		last := 0
		for _, loc := range varRe.FindAllStringSubmatchIndex(p, -1) {
			b.WriteString(textHTML(p[last:loc[0]], accent))
			name := p[loc[2]:loc[3]]
			if val := v.get(name); name == "link" && val != "" {
				b.WriteString(link(val, val, accent))
			} else {
				b.WriteString(html.EscapeString(val))
			}
			last = loc[1]
		}
		b.WriteString(textHTML(p[last:], accent))
		b.WriteString("</p>\n")
	}
	return b.String()
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

var layout = htmltemplate.Must(htmltemplate.New("layout").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Subject}}</title></head>
<body style="margin:0;padding:0;background:#f4f4f7">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f4f4f7"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;background:#ffffff;border-radius:8px;border-top:4px solid {{.Accent}}">
<tr><td style="padding:24px 32px 8px 32px;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif">
{{- if .Logo}}<img src="{{.Logo}}" alt="{{.Name}}" height="40" style="display:block;height:40px;max-width:240px;border:0">{{else}}<span style="font-size:18px;font-weight:700;color:#111">{{.Name}}</span>{{end -}}
</td></tr>
<tr><td style="padding:8px 32px 24px 32px;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;font-size:15px;line-height:1.55;color:#222">
{{.Body}}</td></tr>
</table>
{{- if .Footer}}
<p style="max-width:560px;margin:16px auto 0 auto;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;font-size:12px;line-height:1.5;color:#777">{{.Footer}}</p>
{{- end}}
</td></tr></table>
</body></html>
`))

type layoutData struct {
	Subject string
	Accent  htmltemplate.CSS
	Logo    string
	Name    string
	Body    htmltemplate.HTML
	Footer  htmltemplate.HTML
}

// branded renders tpl (with overrides from cfg and over) into the branded
// layout. logo is the logo URL ("" = the sender name as text).
func branded(tpl template, cfg *config.EmailConfig, over *config.EmailTemplate, v Vars, logo string) (Rendered, error) {
	subject, body := tpl.subject, tpl.body
	if cfg != nil {
		if t, ok := cfg.Templates[tpl.name]; ok {
			if t.Subject != nil {
				subject = *t.Subject
			}
			if t.Body != nil {
				body = *t.Body
			}
		}
	}
	if over != nil {
		if over.Subject != nil {
			subject = *over.Subject
		}
		if over.Body != nil {
			body = *over.Body
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
			logo = ""
		}
	}
	r := Rendered{Subject: strings.Join(strings.Fields(substitute(subject, v)), " ")}
	// Plain-text part: the body with the variables filled in.
	text := strings.Join(paragraphs(substitute(body, v)), "\n\n") + "\n"
	if footer != "" {
		text += "\n-- \n" + footer + "\n"
	}
	r.Text = text
	var footerHTML string
	if footer != "" {
		footerHTML = textHTML(footer, accent)
	}
	var buf bytes.Buffer
	err := layout.Execute(&buf, layoutData{
		Subject: r.Subject, Accent: htmltemplate.CSS(accent), Logo: logo, Name: name,
		Body: htmltemplate.HTML(bodyHTML(body, v, tpl.button, accent)), Footer: htmltemplate.HTML(footerHTML),
	})
	if err != nil {
		return Rendered{}, fmt.Errorf("email layout: %w", err)
	}
	r.HTML = buf.String()
	return r, nil
}
