package email

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	texttemplate "text/template"
)

//go:generate go run ./gen

// The branded layout is templates/layout.mjml, compiled by MJML at build
// time (go generate: ./gen runs mjml-go, MJML as wasm) into
// templates/compiled/*.html, which is embedded and committed; CI fails
// when they differ from a fresh compile. The server never links MJML.
// When the email service starts, the compiled HTML is cut into a
// skeleton: literal HTML with slots. Rendering an email only fills the
// slots, so it costs microseconds and MJML never sees user data. Each slot has one escaping rule (fill):
// text slots are HTML-escaped, URL slots must be http(s) and are escaped,
// colour slots must be #rrggbb, and the HTML slots take only safeHTML,
// which this package builds from escaped text (render.go).

// palette is the layout's colours: Boson's Terminal theme (dark, the
// inline colours every client shows by default) and Daylight (light, with
// prefers-color-scheme: light in Apple Mail, iOS Mail, Outlook for Mac).
// Every text colour has at least 4.5:1 contrast on its page and card
// (TestPaletteContrast).
type palette struct{ Page, Card, Border, Heading, Text, Muted string }

var (
	darkPalette  = palette{Page: "#070709", Card: "#0d0d11", Border: "#24242e", Heading: "#e2e2ea", Text: "#c4c4ce", Muted: "#8e8e9e"}
	lightPalette = palette{Page: "#f4f4f0", Card: "#ffffff", Border: "#d6d6ce", Heading: "#1b1b21", Text: "#3a3a44", Muted: "#5e5e6a"}
)

// The layout's font stacks. Web fonts can't be relied on in email, so
// JetBrains Mono and Inter are named first and the system fonts follow.
const (
	monoFonts = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"
	sansFonts = "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
)

type slot uint8

const (
	slotLiteral  slot = iota
	slotTitle         // text: the subject (title and heading)
	slotPrompt        // text: the command on the prompt line ($ verify --email)
	slotPreview       // text: the inbox preview line
	slotHeader        // safeHTML: logo or sender name
	slotPara          // safeHTML: a run of paragraphs
	slotHref          // URL: the button's link
	slotLabel         // text: the button's label
	slotFooter        // safeHTML: the footer
	slotAccent        // colour: auth.email.accent
	slotOnAccent      // colour: text on the accent (button label)
)

// slotTokens are the placeholders in layout.mjml. The colours are
// sentinels (MJML copies colours into attributes and CSS as they are).
var slotTokens = map[string]slot{
	"BXSLOT_TITLE": slotTitle, "BXSLOT_PROMPT": slotPrompt, "BXSLOT_PREVIEW": slotPreview, "BXSLOT_HEADER": slotHeader,
	"BXSLOT_PARA": slotPara, "BXSLOT_HREF": slotHref, "BXSLOT_LABEL": slotLabel, "BXSLOT_FOOTER": slotFooter,
	"#0b05e1": slotAccent, "#0b05e2": slotOnAccent,
}

var slotRe = regexp.MustCompile(`BXSLOT_[A-Z]+|#0b05e[0-9a-f]`)

// The markers that cut the compiled body into head | paragraph row |
// button row | note row (a paragraph after the button) | middle |
// fallback-link row (only with a button) | tail.
const (
	markPara   = "<!--bx:para-->"
	markButton = "<!--bx:button-->"
	markNote   = "<!--bx:note-->"
	markEnd    = "<!--bx:end-->"
	markAlt    = "<!--bx:alt-->"
	markAltEnd = "<!--bx:altend-->"
)

type part struct {
	slot slot
	lit  string
}

// skeleton is one compiled layout variant.
type skeleton struct {
	head, para, button, note, mid, alt, tail []part
	size                                     int // bytes of literal HTML
}

// safeHTML is HTML this package built from escaped text; nothing else may
// fill an HTML slot.
type safeHTML string

// block is one row of the body: paragraphs, or the action button.
type block struct {
	html        safeHTML
	button      bool
	href, label string
}

// page is what one email fills into a skeleton.
type page struct {
	title, preview   string
	prompt           string
	header, footer   safeHTML
	blocks           []block
	accent, onAccent string
}

var layoutTmpl = texttemplate.Must(texttemplate.ParseFS(templates, "templates/layout.mjml"))

// CompiledLayoutFiles are the go:generate outputs (relative to this
// package), without and with a footer.
var CompiledLayoutFiles = [2]string{"templates/compiled/layout.html", "templates/compiled/layout-footer.html"}

// layouts parses the two compiled variants (without and with a footer)
// the first time an email service is built; every later email reuses them.
var layouts = sync.OnceValues(func() ([2]*skeleton, error) {
	var out [2]*skeleton
	for i, footer := range []bool{false, true} {
		b, err := templates.ReadFile(CompiledLayoutFiles[i])
		if err != nil {
			return out, fmt.Errorf("email layout: %w (run go generate ./internal/services/email)", err)
		}
		sk, err := parseSkeleton(string(b), footer)
		if err != nil {
			return out, err
		}
		out[i] = sk
	}
	return out, nil
})

// LayoutMJML renders layout.mjml for a variant: the MJML go:generate
// compiles into CompiledLayoutFiles[footer].
func LayoutMJML(footer bool) (string, error) {
	var src bytes.Buffer
	err := layoutTmpl.Execute(&src, struct {
		Light, Dark palette
		Mono, Sans  string
		Footer      bool
	}{lightPalette, darkPalette, monoFonts, sansFonts, footer})
	return src.String(), err
}

// parseSkeleton cuts compiled HTML at the markers and the slot tokens, and
// checks every slot is where the fill rules expect it.
func parseSkeleton(out string, footer bool) (*skeleton, error) {
	var cut [7]string
	rest, ok := out, true
	for i, m := range []string{markPara, markButton, markNote, markEnd, markAlt, markAltEnd} {
		var found bool
		cut[i], rest, found = strings.Cut(rest, m)
		ok = ok && found
	}
	cut[6] = rest
	if !ok || strings.Contains(rest, "<!--bx:") {
		return nil, errors.New("email layout: markers missing from the compiled HTML")
	}
	head, para, button, note, mid, alt, tail := cut[0], cut[1], cut[2], cut[3], cut[4], cut[5], cut[6]
	sk := &skeleton{}
	regions := []struct {
		dst          *[]part
		src          string
		allow, needs []slot
	}{
		{&sk.head, head, []slot{slotTitle, slotPrompt, slotPreview, slotHeader, slotAccent}, []slot{slotTitle, slotPrompt, slotPreview, slotHeader, slotAccent}},
		{&sk.para, para, []slot{slotPara}, []slot{slotPara}},
		{&sk.button, button, []slot{slotHref, slotLabel, slotAccent, slotOnAccent}, []slot{slotHref, slotLabel, slotAccent, slotOnAccent}},
		{&sk.note, note, []slot{slotPara}, []slot{slotPara}},
		{&sk.mid, mid, nil, nil},
		{&sk.alt, alt, []slot{slotHref}, []slot{slotHref}},
		{&sk.tail, tail, []slot{slotFooter}, nil},
	}
	if footer {
		regions[len(regions)-1].needs = []slot{slotFooter}
	}
	for _, r := range regions {
		seen := map[slot]bool{}
		last := 0
		for _, loc := range slotRe.FindAllStringIndex(r.src, -1) {
			s, ok := slotTokens[r.src[loc[0]:loc[1]]]
			if !ok || !slices.Contains(r.allow, s) {
				return nil, fmt.Errorf("email layout: unexpected %q in the compiled HTML", r.src[loc[0]:loc[1]])
			}
			seen[s] = true
			*r.dst = append(*r.dst, part{lit: r.src[last:loc[0]]}, part{slot: s})
			sk.size += loc[0] - last
			last = loc[1]
		}
		*r.dst = append(*r.dst, part{lit: r.src[last:]})
		sk.size += len(r.src) - last
		for _, s := range r.needs {
			if !seen[s] {
				return nil, fmt.Errorf("email layout: slot %d missing from the compiled HTML", s)
			}
		}
	}
	return sk, nil
}

// fill renders p into the skeleton.
func (sk *skeleton) fill(p page) string {
	var b strings.Builder
	n := sk.size + len(p.header) + len(p.footer) + 3*len(p.title) + len(p.preview) + len(p.prompt)
	for _, bl := range p.blocks {
		n += len(bl.html) + 3*len(bl.href) + len(bl.label)
	}
	b.Grow(n + len(p.blocks)*1536) // + the repeated rows' literal HTML
	accent, onAccent := safeColor(p.accent, DefaultAccent), safeColor(p.onAccent, "#ffffff")
	write := func(parts []part, bl *block) {
		for _, pt := range parts {
			switch pt.slot {
			case slotLiteral:
				b.WriteString(pt.lit)
			case slotTitle:
				b.WriteString(html.EscapeString(p.title))
			case slotPrompt:
				b.WriteString(html.EscapeString(p.prompt))
			case slotPreview:
				b.WriteString(html.EscapeString(p.preview))
			case slotHeader:
				b.WriteString(string(p.header))
			case slotFooter:
				b.WriteString(string(p.footer))
			case slotAccent:
				b.WriteString(accent)
			case slotOnAccent:
				b.WriteString(onAccent)
			case slotPara:
				b.WriteString(string(bl.html))
			case slotHref:
				b.WriteString(html.EscapeString(safeURL(bl.href)))
			case slotLabel:
				b.WriteString(html.EscapeString(bl.label))
			}
		}
	}
	write(sk.head, nil)
	// Paragraphs after the first button are notes (smaller, muted); the
	// fallback link under the card's rule is the first button's.
	var first *block
	for i := range p.blocks {
		switch {
		case p.blocks[i].button:
			write(sk.button, &p.blocks[i])
			if first == nil {
				first = &p.blocks[i]
			}
		case first != nil:
			write(sk.note, &p.blocks[i])
		default:
			write(sk.para, &p.blocks[i])
		}
	}
	write(sk.mid, nil)
	if first != nil {
		write(sk.alt, first)
	}
	write(sk.tail, nil)
	return b.String()
}

var colorRe = regexp.MustCompile(`^#[0-9a-f]{6}$`)

func safeColor(c, fallback string) string {
	if colorRe.MatchString(c) {
		return c
	}
	return fallback
}

// isHTTP reports whether u is an http(s) URL, the only links emails make.
func isHTTP(u string) bool {
	l := strings.ToLower(u)
	return strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://")
}

func safeURL(u string) string {
	if isHTTP(u) {
		return u
	}
	return "#"
}

// luminance is the WCAG relative luminance of a #rrggbb colour.
func luminance(c string) float64 {
	var l float64
	for i, w := range []float64{0.2126, 0.7152, 0.0722} {
		v, _ := strconv.ParseUint(c[1+2*i:3+2*i], 16, 8)
		s := float64(v) / 255
		if s <= 0.04045 {
			s /= 12.92
		} else {
			s = math.Pow((s+0.055)/1.055, 2.4)
		}
		l += w * s
	}
	return l
}

// contrast is the WCAG contrast ratio of two #rrggbb colours.
func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// onAccentDark is the button label on light accents (Boson's accent-on).
const onAccentDark = "#070709"

// onAccent picks the label colour with the better contrast on accent.
func onAccent(accent string) string {
	if !colorRe.MatchString(accent) {
		return "#ffffff"
	}
	if contrast(accent, "#ffffff") >= contrast(accent, onAccentDark) {
		return "#ffffff"
	}
	return onAccentDark
}

// linkColor is the colour of links in the layout's (dark) card: the
// accent when it reads at 4.5:1 there, else the heading colour. In light
// mode the layout's CSS makes links the light heading colour.
func linkColor(accent string) string {
	if colorRe.MatchString(accent) && contrast(accent, darkPalette.Card) >= 4.5 {
		return accent
	}
	return darkPalette.Heading
}
