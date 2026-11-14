package email

import (
	"bytes"
	"context"
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

	mjml "github.com/Boostport/mjml-go"
)

// The branded layout is templates/layout.mjml, compiled by MJML (as wasm,
// in-process) once per process into an HTML skeleton: literal HTML with
// slots. Rendering an email only fills the slots, so it costs microseconds
// and MJML never sees user data. Each slot has one escaping rule (fill):
// text slots are HTML-escaped, URL slots must be http(s) and are escaped,
// colour slots must be #rrggbb, and the HTML slots take only safeHTML,
// which this package builds from escaped text (render.go).

// palette is the layout's colours; Dark applies with prefers-color-scheme:
// dark (Apple Mail, iOS Mail, Outlook.com via data-ogsc). The light colours
// are soft enough for the clients that invert on their own (Gmail apps).
type palette struct{ Page, Card, Heading, Text, Muted string }

var (
	lightPalette = palette{Page: "#f4f4f7", Card: "#ffffff", Heading: "#111118", Text: "#2b2b33", Muted: "#6b6b78"}
	darkPalette  = palette{Page: "#0f0f13", Card: "#1b1b22", Heading: "#f5f5f8", Text: "#e3e3ea", Muted: "#9d9dab"}
)

type slot uint8

const (
	slotLiteral  slot = iota
	slotTitle         // text: the subject
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
	"BXSLOT_TITLE": slotTitle, "BXSLOT_PREVIEW": slotPreview, "BXSLOT_HEADER": slotHeader,
	"BXSLOT_PARA": slotPara, "BXSLOT_HREF": slotHref, "BXSLOT_LABEL": slotLabel, "BXSLOT_FOOTER": slotFooter,
	"#0b05e1": slotAccent, "#0b05e2": slotOnAccent,
}

var slotRe = regexp.MustCompile(`BXSLOT_[A-Z]+|#0b05e[0-9a-f]`)

// The markers that cut the compiled body into head | paragraph row |
// button row | tail.
const (
	markPara   = "<!--bx:para-->"
	markButton = "<!--bx:button-->"
	markEnd    = "<!--bx:end-->"
)

type part struct {
	slot slot
	lit  string
}

// skeleton is one compiled layout variant.
type skeleton struct {
	head, para, button, tail []part
	size                     int // bytes of literal HTML
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
	header, footer   safeHTML
	blocks           []block
	accent, onAccent string
}

var layoutTmpl = texttemplate.Must(texttemplate.ParseFS(templates, "templates/layout.mjml"))

// layouts compiles the two variants (without and with a footer) the first
// time an email service is built; every later email reuses them.
var layouts = sync.OnceValues(func() ([2]*skeleton, error) {
	var out [2]*skeleton
	for i, footer := range []bool{false, true} {
		sk, err := compileLayout(context.Background(), footer)
		if err != nil {
			return out, err
		}
		out[i] = sk
	}
	return out, nil
})

// mjmlSource renders layout.mjml for a variant.
func mjmlSource(footer bool) (string, error) {
	var src bytes.Buffer
	err := layoutTmpl.Execute(&src, struct {
		Light, Dark palette
		Footer      bool
	}{lightPalette, darkPalette, footer})
	return src.String(), err
}

func compileLayout(ctx context.Context, footer bool) (*skeleton, error) {
	src, err := mjmlSource(footer)
	if err != nil {
		return nil, fmt.Errorf("email layout: %w", err)
	}
	// No web fonts (the system stack names Roboto, which MJML would
	// otherwise import from Google Fonts); strict validation so a broken
	// layout fails the tests; keep comments (markers, Outlook conditionals).
	out, err := mjml.ToHTML(ctx, src, mjml.WithFonts(mjml.Fonts{}),
		mjml.WithValidationLevel(mjml.Strict), mjml.WithKeepComments(true))
	if err != nil {
		return nil, fmt.Errorf("email layout: mjml: %w", err)
	}
	return parseSkeleton(out, footer)
}

// parseSkeleton cuts compiled HTML at the markers and the slot tokens, and
// checks every slot is where the fill rules expect it.
func parseSkeleton(out string, footer bool) (*skeleton, error) {
	head, rest, ok1 := strings.Cut(out, markPara)
	para, rest, ok2 := strings.Cut(rest, markButton)
	button, tail, ok3 := strings.Cut(rest, markEnd)
	if !ok1 || !ok2 || !ok3 || strings.Contains(tail, "<!--bx:") {
		return nil, errors.New("email layout: markers missing from the compiled HTML")
	}
	sk := &skeleton{}
	regions := []struct {
		dst          *[]part
		src          string
		allow, needs []slot
	}{
		{&sk.head, head, []slot{slotTitle, slotPreview, slotHeader, slotAccent}, []slot{slotTitle, slotPreview, slotHeader, slotAccent}},
		{&sk.para, para, []slot{slotPara}, []slot{slotPara}},
		{&sk.button, button, []slot{slotHref, slotLabel, slotAccent, slotOnAccent}, []slot{slotHref, slotLabel, slotAccent, slotOnAccent}},
		{&sk.tail, tail, []slot{slotFooter}, nil},
	}
	if footer {
		regions[3].needs = []slot{slotFooter}
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
	n := sk.size + len(p.header) + len(p.footer) + 2*len(p.title) + len(p.preview)
	for _, bl := range p.blocks {
		n += len(bl.html) + len(bl.href) + len(bl.label)
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
	for i := range p.blocks {
		if p.blocks[i].button {
			write(sk.button, &p.blocks[i])
		} else {
			write(sk.para, &p.blocks[i])
		}
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

// onAccent picks the label colour with the better contrast on accent.
func onAccent(accent string) string {
	lum := func(c string) float64 {
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
	if !colorRe.MatchString(accent) {
		return "#ffffff"
	}
	a := lum(accent)
	// Contrast with white (1.0) vs with #111118 (~0.0056).
	if (1.05)/(a+0.05) >= (a+0.05)/(0.0056+0.05) {
		return "#ffffff"
	}
	return "#111118"
}
