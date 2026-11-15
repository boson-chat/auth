package email

import (
	"crypto/sha256"
	"fmt"
	"html"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	nethtml "golang.org/x/net/html"
)

// Custom HTML: an admin's layout (auth.email.layout) or a whole email
// (auth.email.templates.<name>), MJML compiled to HTML in the admin
// panel's browser. auth never runs MJML on it; it finds the {{placeholders}}
// once, when the file is loaded, notes the HTML context of each one (body
// text, an attribute, a URL attribute, CSS, a script, inside a tag) and
// fills them on every email with the escaping that context needs. The
// substitution is a single pass over the parsed parts, so a value is never
// scanned for placeholders again.

// phKind is what a placeholder is filled with.
type phKind uint8

const (
	phText    phKind = iota // plain text
	phURL                   // an http(s) URL
	phColor                 // #rrggbb
	phContent               // the layout's body: HTML auth builds (layout only)
)

// placeholders are the names a custom document may use.
var placeholders = map[string]phKind{
	"subject": phText, "network": phText, "username": phText, "inviter": phText, "expires": phText,
	"footer": phText, "sender_name": phText,
	"link": phURL, "logo_url": phURL,
	"accent": phColor, "accent_text": phColor,
	"content": phContent,
}

// phRe matches {{name}}, spaces inside the braces allowed.
var phRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}`)

// hctx is the HTML context of a placeholder.
type hctx uint8

const (
	ctxText    hctx = iota // element content
	ctxRCDATA              // <title>, <textarea>: text, no markup
	ctxComment             // an HTML comment
	ctxAttr                // a (non-URL, non-style) attribute value
	ctxURL                 // a URL attribute value (href, src, ...)
	ctxCSS                 // a style attribute or <style>
	ctxScript              // <script> or an on* attribute
	ctxTag                 // inside a tag, outside any attribute value
)

var ctxNames = [...]string{"text", "a title", "a comment", "an attribute", "a URL attribute", "CSS", "a script", "a tag"}

// docPart is literal HTML or one placeholder.
type docPart struct {
	lit  string
	name string // "" = literal
	kind phKind
	ctx  hctx
	// attr: inside an attribute value; quoted: that value is quoted;
	// start: the placeholder starts the URL (nothing but spaces before it).
	attr, quoted, start bool
}

// customDoc is a parsed custom HTML document.
type customDoc struct {
	parts    []docPart
	size     int
	warnings []string
	// hash identifies the source (preview cache).
	hash [32]byte
}

// docError is a problem with a custom document's placeholders.
type docError struct{ msg string }

func (e *docError) Error() string { return e.msg }

// position is "line L, column C" of byte offset off in src.
func position(src string, off int) string {
	line := 1 + strings.Count(src[:off], "\n")
	col := 1 + utf8.RuneCountInString(src[strings.LastIndexByte(src[:off], '\n')+1:off])
	return fmt.Sprintf("line %d, column %d", line, col)
}

// rawTextElems hold raw text up to their end tag.
var rawTextElems = map[string]hctx{"style": ctxCSS, "script": ctxScript, "title": ctxRCDATA, "textarea": ctxRCDATA,
	"xmp": ctxRCDATA, "iframe": ctxRCDATA, "noembed": ctxRCDATA, "noframes": ctxRCDATA, "noscript": ctxRCDATA, "plaintext": ctxRCDATA}

// urlAttrs hold URLs.
var urlAttrs = map[string]bool{"href": true, "src": true, "action": true, "formaction": true, "background": true, "cite": true,
	"poster": true, "longdesc": true, "usemap": true, "xlink:href": true, "srcset": true, "data": true, "codebase": true,
	"profile": true, "manifest": true, "icon": true, "lowsrc": true, "dynsrc": true}

// compileDoc parses src. layout: src is the layout ({{content}} exactly
// once, in the body text); otherwise a whole email ({{link}} required).
func compileDoc(src string, layout bool) (*customDoc, error) {
	if len(src) > maxCustomBytes {
		return nil, &docError{fmt.Sprintf("must be at most %d KB, got %d KB", maxCustomBytes>>10, (len(src)+1023)>>10)}
	}
	d := &customDoc{hash: sha256.Sum256([]byte(src))}
	type found struct {
		off    int
		name   string
		ctx    hctx
		attr   bool
		quoted bool
		start  bool
		end    int
	}
	var phs []found
	add := func(f found) { phs = append(phs, f) }
	var scan func(base, end int)
	// scanSpan finds the placeholders in src[from:to] in context c.
	scanSpan := func(from, to int, c hctx, attr, quoted, start bool, vstart int) {
		for _, m := range phRe.FindAllStringSubmatchIndex(src[from:to], -1) {
			f := found{off: from + m[0], end: from + m[1], name: src[from+m[2] : from+m[3]], ctx: c, attr: attr, quoted: quoted}
			if c == ctxURL {
				f.start = strings.TrimSpace(src[vstart:f.off]) == ""
			}
			add(f)
		}
	}
	scan = func(base, end int) {
		z := nethtml.NewTokenizer(strings.NewReader(src[base:end]))
		off := base
		raw := hctx(255) // the raw-text element just opened
		for {
			tt := z.Next()
			if tt == nethtml.ErrorToken {
				if z.Err() != io.EOF {
					return
				}
				// Anything the tokenizer didn't return (none expected) is text.
				if off < end {
					scanSpan(off, end, ctxText, false, false, false, 0)
				}
				return
			}
			n := len(z.Raw())
			from, to := off, off+n
			off = to
			switch tt {
			case nethtml.TextToken:
				c := ctxText
				if raw != 255 {
					c = raw
				}
				scanSpan(from, to, c, false, false, false, 0)
				raw = 255
			case nethtml.CommentToken:
				raw = 255
				tok := src[from:to]
				// Outlook's conditional comments hold markup: scan it as HTML.
				if strings.HasPrefix(tok, "<!--[if") {
					if i := strings.Index(tok, "]>"); i >= 0 {
						inner := from + i + 2
						innerEnd := to
						if j := strings.LastIndex(tok, "<![endif]"); j > i {
							innerEnd = from + j
						}
						scanSpan(from, inner, ctxTag, false, false, false, 0)
						scan(inner, innerEnd)
						scanSpan(innerEnd, to, ctxTag, false, false, false, 0)
						continue
					}
				}
				scanSpan(from, to, ctxComment, false, false, false, 0)
			case nethtml.StartTagToken, nethtml.SelfClosingTagToken:
				name, attrs := scanTag(src[from:to])
				raw = 255
				if c, ok := rawTextElems[name]; ok && tt == nethtml.StartTagToken {
					raw = c
				}
				last := from
				for _, a := range attrs {
					vs, ve := from+a.vstart, from+a.vend
					scanSpan(last, vs, ctxTag, false, false, false, 0)
					c := ctxAttr
					switch {
					case a.name == "style":
						c = ctxCSS
					case strings.HasPrefix(a.name, "on"):
						c = ctxScript
					case urlAttrs[a.name]:
						c = ctxURL
					}
					scanSpan(vs, ve, c, true, a.quoted, false, vs)
					last = ve
				}
				scanSpan(last, to, ctxTag, false, false, false, 0)
			default: // end tags, doctype
				raw = 255
				scanSpan(from, to, ctxTag, false, false, false, 0)
			}
		}
	}
	scan(0, len(src))

	var contents, links []string
	last := 0
	for _, f := range phs {
		at := position(src, f.off)
		kind, known := placeholders[f.name]
		literal := false
		switch {
		case !known:
			d.warnings = append(d.warnings, fmt.Sprintf("unknown placeholder {{%s}} at %s is left as written", f.name, at))
			literal = true
		case kind == phContent && !layout:
			d.warnings = append(d.warnings, fmt.Sprintf("{{content}} at %s is only for the layout; in a whole email it is left as written", at))
			literal = true
		case kind == phContent && f.ctx != ctxText:
			return nil, &docError{fmt.Sprintf("{{content}} at %s must be in the body text, not in %s", at, ctxNames[f.ctx])}
		case kind == phContent:
			contents = append(contents, at)
		case f.ctx == ctxTag:
			d.warnings = append(d.warnings, fmt.Sprintf("{{%s}} at %s is inside a tag but not in an attribute value; it is left out", f.name, at))
		case f.ctx == ctxScript && kind != phColor:
			d.warnings = append(d.warnings, fmt.Sprintf("{{%s}} at %s is in a script; it is left out", f.name, at))
		case f.ctx == ctxCSS && kind == phText:
			d.warnings = append(d.warnings, fmt.Sprintf("{{%s}} at %s is in CSS: only letters, digits, spaces and . , - _ # %% are kept", f.name, at))
		}
		if kind == phURL && f.name == "link" && f.ctx != ctxTag && f.ctx != ctxScript && known {
			links = append(links, at)
		}
		if literal {
			continue
		}
		d.parts = append(d.parts, docPart{lit: src[last:f.off]})
		d.parts = append(d.parts, docPart{name: f.name, kind: kind, ctx: f.ctx, attr: f.attr, quoted: f.quoted, start: f.start})
		d.size += f.off - last
		last = f.end
	}
	d.parts = append(d.parts, docPart{lit: src[last:]})
	d.size += len(src) - last
	if layout && len(contents) != 1 {
		if len(contents) == 0 {
			return nil, &docError{"must contain {{content}} (where the email's text and button go)"}
		}
		return nil, &docError{fmt.Sprintf("must contain {{content}} exactly once, found %d (%s)", len(contents), strings.Join(contents, "; "))}
	}
	if !layout && len(links) == 0 {
		return nil, &docError{"must contain {{link}} (the email's action link)"}
	}
	return d, nil
}

// maxCustomBytes is config.MaxEmailFileBytes (repeated to keep this file
// free of the config import).
const maxCustomBytes = 512 << 10

type tagAttr struct {
	name         string
	vstart, vend int // value span in the tag (vstart == vend: empty)
	quoted       bool
}

// scanTag splits a raw start tag into its name and attributes with their
// value spans, following the HTML tokenizer's rules.
func scanTag(t string) (string, []tagAttr) {
	i := 1 // past '<'
	for i < len(t) && !isSpace(t[i]) && t[i] != '/' && t[i] != '>' {
		i++
	}
	name := strings.ToLower(t[1:i])
	var attrs []tagAttr
	for i < len(t) {
		for i < len(t) && (isSpace(t[i]) || t[i] == '/') {
			i++
		}
		if i >= len(t) || t[i] == '>' {
			break
		}
		ns := i
		i++ // a name may start with '='
		for i < len(t) && !isSpace(t[i]) && t[i] != '/' && t[i] != '>' && t[i] != '=' {
			i++
		}
		a := tagAttr{name: strings.ToLower(t[ns:i])}
		j := i
		for j < len(t) && isSpace(t[j]) {
			j++
		}
		if j >= len(t) || t[j] != '=' {
			a.vstart, a.vend = i, i
			attrs = append(attrs, a)
			continue
		}
		j++
		for j < len(t) && isSpace(t[j]) {
			j++
		}
		if j < len(t) && (t[j] == '"' || t[j] == '\'') {
			q := t[j]
			k := strings.IndexByte(t[j+1:], q)
			if k < 0 {
				k = len(t) - j - 1
			}
			a.vstart, a.vend, a.quoted = j+1, j+1+k, true
			i = min(j+2+k, len(t))
		} else {
			k := j
			for k < len(t) && !isSpace(t[k]) && t[k] != '>' {
				k++
			}
			a.vstart, a.vend = j, k
			i = k
		}
		attrs = append(attrs, a)
	}
	return name, attrs
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }

// docValues fill a custom document.
type docValues struct {
	text          map[string]string // phText values
	link, logoURL string            // http(s) or ""
	accent        string            // #rrggbb
	content       safeHTML
}

// fill renders the document; each placeholder is escaped for its context.
func (d *customDoc) fill(v docValues) string {
	var b strings.Builder
	b.Grow(d.size + len(v.content) + 1024)
	for _, p := range d.parts {
		if p.name == "" {
			b.WriteString(p.lit)
			continue
		}
		b.WriteString(fillPart(p, v))
	}
	return b.String()
}

func fillPart(p docPart, v docValues) string {
	switch p.kind {
	case phColor:
		// [#0-9a-f] only: safe anywhere.
		if p.name == "accent_text" {
			return onAccent(safeColor(v.accent, DefaultAccent))
		}
		return safeColor(v.accent, DefaultAccent)
	case phContent:
		return string(v.content) // ctxText only (compileDoc)
	}
	var val string
	if p.kind == phURL {
		u := v.logoURL
		if p.name == "link" {
			u = v.link
		}
		if isHTTP(u) {
			val = u
		} else if p.name == "link" {
			val = "#"
		}
	} else {
		val = v.text[p.name]
	}
	switch p.ctx {
	case ctxText, ctxRCDATA, ctxComment:
		return html.EscapeString(val)
	case ctxAttr:
		return attrEscape(val, p.quoted)
	case ctxURL:
		// A URL placeholder may start the URL; anything else is a part of
		// one (a query value), percent-encoded so it can't add a scheme.
		if p.kind != phURL || !p.start {
			val = url.QueryEscape(val)
		}
		return attrEscape(val, p.quoted)
	case ctxCSS:
		if p.kind == phURL {
			val = cssURL(val)
		} else {
			val = cssText(val)
		}
		if p.attr {
			return attrEscape(val, p.quoted)
		}
		return val // <style>: raw text; neither filter lets '<' through
	}
	return "" // script, tag
}

// attrEscape escapes an attribute value; unquoted values also lose the
// characters that would end them.
func attrEscape(s string, quoted bool) string {
	s = html.EscapeString(s)
	if quoted {
		return s
	}
	return unquotedRepl.Replace(s)
}

var unquotedRepl = strings.NewReplacer(" ", "&#32;", "\t", "&#9;", "\n", "&#10;", "\r", "&#13;", "\f", "&#12;", "=", "&#61;", "`", "&#96;")

// cssText keeps letters, digits, spaces and . , - _ # %.
func cssText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(" .,-_#%", r) {
			return r
		}
		return -1
	}, s)
}

// cssURL percent-encodes everything but the URL characters that can't end
// a CSS string, url() or declaration.
func cssURL(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~:/?#@$&*+,=%", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// contentHTML is {{content}}: the body's paragraphs and buttons as HTML
// that sits in the layout's text column.
func contentHTML(blocks []block, accent string) safeHTML {
	accent = safeColor(accent, DefaultAccent)
	label := onAccent(accent)
	var b strings.Builder
	for _, bl := range blocks {
		if !bl.button {
			b.WriteString(string(bl.html))
			continue
		}
		href := html.EscapeString(safeURL(bl.href))
		b.WriteString(buttonHTML(href, html.EscapeString(bl.label), accent, label, "margin:4px 0 12px 0"))
		if href != "#" {
			b.WriteString(`<p style="margin:0 0 20px 0;font-size:12px;line-height:18px">Button not working? Paste this link into your browser:<br>` +
				`<a href="` + href + `" style="color:inherit;font-family:` + monoFonts + `;text-decoration:underline;word-break:break-all">` + href + `</a></p>`)
		}
		b.WriteString("\n")
	}
	return safeHTML(b.String())
}

// buttonHTML is a bulletproof button (the table mj-button makes). href,
// label and the colours are already escaped (or placeholders).
func buttonHTML(href, label, accent, color, margin string) string {
	return `<table role="presentation" border="0" cellpadding="0" cellspacing="0" style="border-collapse:separate;line-height:100%;` + margin + `"><tr>` +
		`<td align="center" bgcolor="` + accent + `" role="presentation" style="border:none;border-radius:2px;cursor:auto;mso-padding-alt:12px 20px;background:` + accent + `" valign="middle">` +
		`<a href="` + href + `" class="bx-mono" style="display:inline-block;background:` + accent + `;color:` + color +
		`;font-family:` + monoFonts + `;font-size:14px;font-weight:600;line-height:20px;margin:0;text-decoration:none;text-transform:none;padding:12px 20px;mso-padding-alt:0px;border-radius:2px;word-break:normal" target="_blank">` +
		label + `</a></td></tr></table>`
}

// CheckCustomHTML validates compiled MJML as a layout or a whole email,
// the rules LoadFiles and the preview apply.
func CheckCustomHTML(src string, layout bool) error {
	_, err := compileDoc(src, layout)
	return err
}
