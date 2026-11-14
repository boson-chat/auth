package email

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
)

// Boson's default MJML, the starting point of the admin panel's MJML
// editor (GET /internal/email/default-mjml). It is templates/layout.mjml
// with the build-time slots turned into the {{placeholders}} of a custom
// layout; a template's default is that layout with the template's default
// text and button in place of {{content}}.

// DefaultMJMLTestdata is where go generate writes the compiled default
// MJML (relative to this package; tests only).
const DefaultMJMLTestdata = "testdata/default-mjml"

// MJMLParts are the parts with a default MJML source.
var MJMLParts = append([]string{"layout"}, config.EmailTemplates...)

// ErrUnknownPart: part is not one of MJMLParts.
var ErrUnknownPart = apperr.InvalidField("part", "must be one of "+strings.Join(MJMLParts, ", "))

// bodyRowsRe is the paragraph and button rows of layout.mjml.
var bodyRowsRe = regexp.MustCompile(`(?s)<mj-raw><!--bx:para--></mj-raw>.*<mj-raw><!--bx:end--></mj-raw>`)

// previewRe is the inbox preview line (filled from the body by auth's own
// layout; a custom layout has no placeholder for it).
var previewRe = regexp.MustCompile(`\n[ \t]*<mj-preview>BXSLOT_PREVIEW</mj-preview>`)

// DefaultMJML returns the default MJML source of part ("layout" or a
// template name).
func DefaultMJML(part string) (string, error) {
	src, err := LayoutMJML(true)
	if err != nil {
		return "", err
	}
	layoutContent := `<mj-text css-class="bx-text">{{content}}</mj-text>`
	content := layoutContent
	if part != "layout" {
		tpl, ok := catalog[part]
		if !ok {
			return "", ErrUnknownPart
		}
		content = templateMJML(tpl)
	}
	src = previewRe.ReplaceAllString(src, "")
	src = bodyRowsRe.ReplaceAllLiteralString(src, content)
	src = strings.NewReplacer(
		"BXSLOT_TITLE", "{{subject}}",
		"BXSLOT_HEADER", "{{sender_name}}",
		"BXSLOT_FOOTER", "{{footer}}",
		"#0b05e1", "{{accent}}",
	).Replace(src)
	if strings.Contains(src, "BXSLOT_") || strings.Contains(src, "#0b05e") || part == "layout" && !strings.Contains(src, layoutContent) {
		return "", fmt.Errorf("email: default MJML for %s: layout.mjml changed shape", part)
	}
	return src, nil
}

// mjmlText escapes text for MJML (XML-like markup; line breaks as <br>).
var mjmlText = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\n", "<br>")

// templateMJML is tpl's default body as MJML: a text block per run of
// paragraphs and an mj-button for the action link alone in its paragraph.
// The variables stay {{placeholders}}.
func templateMJML(tpl template) string {
	const indent = "\n          "
	var out []string
	var run []string
	flush := func() {
		if len(run) > 0 {
			out = append(out, `<mj-text css-class="bx-text">`+strings.Join(run, "")+`</mj-text>`)
			run = nil
		}
	}
	for _, p := range paragraphs(tpl.body) {
		if m := varRe.FindStringSubmatch(p); m != nil && m[0] == p && m[1] == "link" {
			flush()
			// Raw HTML rather than mj-button: MJML's validator rejects
			// {{accent}} as a colour attribute.
			out = append(out, `<mj-raw><tr><td align="left" class="bx-btn" style="font-size:0px;padding:4px 32px 20px 32px;word-break:break-word">`+
				buttonHTML("{{link}}", mjmlText.Replace(tpl.button), "{{accent}}", "#ffffff", "")+`</td></tr></mj-raw>`)
			continue
		}
		var b strings.Builder
		b.WriteString(`<p style="margin:0 0 16px 0">`)
		last := 0
		for _, loc := range varRe.FindAllStringSubmatchIndex(p, -1) {
			b.WriteString(mjmlText.Replace(p[last:loc[0]]))
			if name := p[loc[2]:loc[3]]; name == "link" {
				b.WriteString(`<a href="{{link}}">{{link}}</a>`)
			} else {
				b.WriteString("{{" + name + "}}")
			}
			last = loc[1]
		}
		b.WriteString(mjmlText.Replace(p[last:]))
		b.WriteString("</p>")
		run = append(run, b.String())
	}
	flush()
	return strings.Join(out, indent)
}
