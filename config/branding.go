package config

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/boson-chat/auth/internal/configfile"
	"github.com/boson-chat/auth/internal/theme"
)

// The branding: section (network theme and images) and auth.email
// (branded, customizable emails) of the stack config file:
//
//	branding:
//	  theme:                        # boson-theme/1 without image URLs
//	    base: dark
//	    colors: { accent: "#7c3aed", bg: "#0b0b10" }
//	    nick: { saturation: 62, lightness: 64 }
//	    radius: 2
//	    font: boson
//	    panes:
//	      messages: { dim: 0.7, blur: 8, position: center }
//	    variants:                   # optional: the other base's version
//	      light:
//	        colors: { accent: "#6d28d9" }
//	        nick: { saturation: 60, lightness: 38 }
//	        panes:
//	          messages: { dim: 0.3 }  # overrides the primary pane's fields
//	  images:                       # files in <config dir>/branding/
//	    logo: logo.svg
//	    login_background: login.webp
//	    panes.messages.image: messages.webp
//	    variants.light.panes.messages.image: messages-light.webp
//	auth:
//	  email:
//	    sender_name: "Example Chat"
//	    accent: "#7c3aed"
//	    footer: "Example Chat · example.com"
//	    logo: true
//	    layout:                     # optional: an admin's MJML layout, files in
//	      mjml: layout-1a2b.mjml    # <config dir>/emails/ (BOSON_EMAILS_DIR)
//	      html: layout-1a2b.html    # compiled HTML (what auth renders)
//	    templates:
//	      verification: { subject: "…", body: "…" }
//	      invite: { mjml: invite-3c4d.mjml, html: invite-3c4d.html }   # whole-email override

// BrandingConfig is the branding: section.
type BrandingConfig struct {
	// Theme has no image URLs; they come from Images.
	Theme  theme.Theme
	Images []BrandingImage
}

// BrandingImage is one entry of branding.images.
type BrandingImage struct {
	Slot string `json:"slot"`
	File string `json:"file"`
	// Line, Column locate the file name in the config file (errors about
	// the file's contents).
	Line   int `json:"-"`
	Column int `json:"-"`
}

// Email template names (auth.email.templates keys, and the template of
// POST /internal/email/preview|test).
const (
	EmailVerification  = "verification"
	EmailPasswordReset = "password_reset"
	EmailAccountSetup  = "account_setup"
	EmailInvite        = "invite"
)

// EmailTemplates lists the template names.
var EmailTemplates = []string{EmailVerification, EmailPasswordReset, EmailAccountSetup, EmailInvite}

// Bounds of auth.email.
const (
	MaxSenderNameLen = 100
	MaxFooterLen     = 500
	MaxSubjectLen    = 200
	MaxBodyLen       = 10000
)

// EmailConfig is auth.email. Its presence (even empty) switches emails to
// the branded layout; without it they are Boson's built-in emails.
type EmailConfig struct {
	SenderName string                   `json:"sender_name,omitempty"`
	Accent     string                   `json:"accent,omitempty"`
	Footer     string                   `json:"footer,omitempty"`
	Logo       bool                     `json:"logo"`
	Templates  map[string]EmailTemplate `json:"templates,omitempty"`
	// Layout is an admin's MJML layout (auth.email.layout); nil = Boson's.
	Layout *EmailFiles `json:"layout,omitempty"`
}

// EmailTemplate overrides one email's wording; nil = Boson's default.
type EmailTemplate struct {
	Subject *string `json:"subject,omitempty"`
	Body    *string `json:"body,omitempty"`
	// Files replaces the whole email (templates.<name>.mjml|html); nil = the
	// layout with Subject / Body.
	Files *EmailFiles `json:"files,omitempty"`
}

// MaxEmailFileBytes bounds each MJML / HTML file of auth.email.
const MaxEmailFileBytes = 512 << 10

// EmailFiles is an MJML source and the HTML the admin panel compiled from
// it, files in the emails directory. Only the HTML is rendered; the MJML is
// kept for re-editing (optional, but checked when named).
type EmailFiles struct {
	MJML string `json:"mjml,omitempty"`
	HTML string `json:"html"`
	// Key is the config path of the files ("auth.email.layout",
	// "auth.email.templates.invite"); Line, Column locate the html key's
	// value (and MJMLLine, MJMLColumn the mjml key's).
	Key                  string `json:"-"`
	Line, Column         int    `json:"-"`
	MJMLLine, MJMLColumn int    `json:"-"`
	// Source is the HTML file's contents, read when the config is loaded
	// (email.LoadFiles).
	Source string `json:"-"`
}

// emailFileRe: a plain file name in the emails directory.
var emailFileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// CheckEmailFileName returns the plain file name of an auth.email file
// reference, which may be written with the directory ("emails/x.html", as
// the admin panel writes it) or without. ext is ".mjml" or ".html".
func CheckEmailFileName(v, ext string) (string, error) {
	name := strings.TrimPrefix(v, "emails/")
	if !emailFileRe.MatchString(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("%q must be a plain file name in the emails directory (letters, digits, . _ -)", v)
	}
	if !strings.EqualFold(path.Ext(name), ext) {
		return "", fmt.Errorf("%q must be a %s file", v, ext)
	}
	return name, nil
}

// loadEmailFiles decodes {mjml, html} under s (key: its config path); nil
// when neither is set.
func loadEmailFiles(s *configfile.Section, key string) (*EmailFiles, error) {
	f := &EmailFiles{Key: key}
	for _, k := range []struct {
		name, ext string
		dst       *string
		line, col *int
	}{{"mjml", ".mjml", &f.MJML, &f.MJMLLine, &f.MJMLColumn}, {"html", ".html", &f.HTML, &f.Line, &f.Column}} {
		var v string
		if err := stringKey(s, k.name, &v, nil); err != nil {
			return nil, err
		}
		if v == "" {
			continue
		}
		name, err := CheckEmailFileName(v, k.ext)
		if err != nil {
			return nil, s.Errorf(k.name, "%s", err.Error())
		}
		n := s.Node(k.name)
		*k.dst, *k.line, *k.col = name, n.Line, n.Column
	}
	if f.HTML == "" && f.MJML == "" {
		return nil, nil
	}
	if f.HTML == "" {
		return nil, s.Errorf("mjml", "needs html too: auth renders the compiled HTML, the MJML is its source")
	}
	return f, nil
}

// Config keys.
const (
	KeyBrandingTheme = "branding.theme"
	KeyBrandingImage = "branding.images." // + slot
	KeyEmail         = "auth.email."      // + field / layout.mjml|html / templates.<name>.subject|body|mjml|html
)

// CheckSubject validates an email subject (file or preview request).
func CheckSubject(v string) string {
	if strings.ContainsAny(v, "\r\n") {
		return "must be one line"
	}
	if len([]rune(v)) > MaxSubjectLen {
		return fmt.Sprintf("must be at most %d characters", MaxSubjectLen)
	}
	if strings.TrimSpace(v) == "" {
		return "can't be empty (remove the key for the default)"
	}
	return ""
}

// CheckBody validates an email body.
func CheckBody(v string) string {
	if len([]rune(v)) > MaxBodyLen {
		return fmt.Sprintf("must be at most %d characters", MaxBodyLen)
	}
	if strings.TrimSpace(v) == "" {
		return "can't be empty (remove the key for the default)"
	}
	if strings.ContainsFunc(v, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' }) {
		return "must not contain control characters"
	}
	return ""
}

// CheckSenderName validates auth.email.sender_name (file or preview request).
func CheckSenderName(v string) string { return checkLine(MaxSenderNameLen)(v) }

// CheckAccent validates auth.email.accent.
func CheckAccent(v string) string { return checkColor(v) }

// CheckFooter validates auth.email.footer.
func CheckFooter(v string) string {
	if len([]rune(v)) > MaxFooterLen {
		return fmt.Sprintf("must be at most %d characters", MaxFooterLen)
	}
	if strings.ContainsFunc(v, func(r rune) bool { return unicode.IsControl(r) && r != '\n' }) {
		return "must not contain control characters"
	}
	return ""
}

func checkLine(maxLen int) func(string) string {
	return func(v string) string {
		if strings.ContainsFunc(v, unicode.IsControl) {
			return "must be one line of text"
		}
		if len([]rune(v)) > maxLen {
			return fmt.Sprintf("must be at most %d characters", maxLen)
		}
		return ""
	}
}

func checkColor(v string) string {
	if !theme.ValidColor(v) {
		return fmt.Sprintf("must be a #rrggbb colour, got %q", v)
	}
	return ""
}

// stringKey reads an optional string, checks it and stores it in dst.
func stringKey(s *configfile.Section, key string, dst *string, check func(string) string) error {
	v, err := s.String(key)
	if err != nil || v == nil {
		return err
	}
	if check != nil {
		if msg := check(*v); msg != "" {
			return s.Errorf(key, "%s", msg)
		}
	}
	*dst = *v
	return nil
}

// imageKeys are theme keys that hold image URLs: images are files listed in
// branding.images, never URLs in the config file.
var imageKeys = []string{"logo", "logo_wide", "login_background", "image"}

func rejectImageKeys(s *configfile.Section) error {
	for _, k := range imageKeys {
		if s.Has(k) {
			return s.Errorf(k, "images are files: list them under branding.images instead")
		}
	}
	return nil
}

// loadBranding decodes the branding: section; nil when absent.
func loadBranding(doc *configfile.Document) (*BrandingConfig, []string, error) {
	sec, err := doc.Section("branding")
	if err != nil || sec == nil {
		return nil, nil, err
	}
	var unknown []string
	b := &BrandingConfig{Theme: theme.Theme{Version: theme.Version, Base: theme.BaseDark}}
	t := &b.Theme
	ts, err := sec.Sub("theme")
	if err != nil {
		return nil, nil, err
	}
	if ts != nil {
		if err := rejectImageKeys(ts); err != nil {
			return nil, nil, err
		}
		v, err := ts.Int("version")
		if err != nil {
			return nil, nil, err
		}
		if v != nil && *v != theme.Version {
			return nil, nil, ts.Errorf("version", "must be %d", theme.Version)
		}
		if err := stringKey(ts, "base", &t.Base, func(v string) string {
			if v != theme.BaseDark && v != theme.BaseLight {
				return fmt.Sprintf("must be dark or light, got %q", v)
			}
			return ""
		}); err != nil {
			return nil, nil, err
		}
		if err := stringKey(ts, "font", &t.Font, func(v string) string {
			if v != theme.FontBoson && v != theme.FontSystem {
				return fmt.Sprintf("must be boson or system, got %q", v)
			}
			return ""
		}); err != nil {
			return nil, nil, err
		}
		r, err := ts.Int("radius")
		if err != nil {
			return nil, nil, err
		}
		if r != nil {
			if msg := theme.CheckRadius(*r); msg != "" {
				return nil, nil, ts.Errorf("radius", "%s", msg)
			}
			t.Radius = r
		}
		var u []string
		if t.Colors, t.Nick, t.Panes, u, err = loadLook(ts); err != nil {
			return nil, nil, err
		}
		unknown = append(unknown, u...)
		if t.Variants, u, err = loadVariants(ts, t.Base); err != nil {
			return nil, nil, err
		}
		unknown = append(unknown, u...)
		unknown = append(unknown, ts.Unknown("version", "base", "colors", "nick", "radius", "font", "panes", "variants")...)
	}
	imgs, err := sec.Sub("images")
	if err != nil {
		return nil, nil, err
	}
	for _, slot := range imgs.Keys() {
		if !theme.ValidSlot(slot) {
			return nil, nil, configfile.At(imgs.KeyNode(slot), "%s.%s: unknown image slot (one of %s)",
				imgs.Path(), slot, strings.Join(theme.Slots(), ", "))
		}
		var file string
		if err := stringKey(imgs, slot, &file, func(v string) string {
			if _, err := theme.CheckFileName(v); err != nil {
				return err.Error()
			}
			return ""
		}); err != nil {
			return nil, nil, err
		}
		if file == "" {
			continue
		}
		if v := theme.SlotVariant(slot); v != "" && t.Variants[v] == nil {
			unknown = append(unknown, imgs.Path()+"."+slot) // no such variant: dropped
			continue
		}
		n := imgs.Node(slot)
		b.Images = append(b.Images, BrandingImage{Slot: slot, File: file, Line: n.Line, Column: n.Column})
	}
	slices.SortFunc(b.Images, func(a, b BrandingImage) int { return strings.Compare(a.Slot, b.Slot) })
	unknown = append(unknown, sec.Unknown("theme", "images")...)
	return b, unknown, nil
}

// loadLook decodes what the primary and each variant have of their own:
// colors, nick and panes (keys of s).
func loadLook(s *configfile.Section) (colors map[string]string, nick *theme.Nick, panes map[string]*theme.Pane, unknown []string, err error) {
	cs, err := s.Sub("colors")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, k := range cs.Keys() {
		if !theme.ValidToken(k) {
			unknown = append(unknown, cs.Path()+"."+k)
			continue
		}
		var c string
		if err := stringKey(cs, k, &c, checkColor); err != nil {
			return nil, nil, nil, nil, err
		}
		if c == "" {
			continue // null
		}
		if colors == nil {
			colors = map[string]string{}
		}
		colors[k] = strings.ToLower(c)
	}
	ns, err := s.Sub("nick")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if ns != nil {
		n := &theme.Nick{}
		for key, dst := range map[string]**int{"saturation": &n.Saturation, "lightness": &n.Lightness} {
			v, err := ns.Int(key)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			if v != nil {
				if msg := theme.CheckNickPercent(*v); msg != "" {
					return nil, nil, nil, nil, ns.Errorf(key, "%s", msg)
				}
				*dst = v
			}
		}
		if n.Saturation != nil || n.Lightness != nil {
			nick = n
		}
		unknown = append(unknown, ns.Unknown("saturation", "lightness")...)
	}
	pss, err := s.Sub("panes")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, name := range pss.Keys() {
		if !theme.ValidPane(name) {
			unknown = append(unknown, pss.Path()+"."+name)
			continue
		}
		ps, err := pss.Sub(name)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if ps == nil {
			continue
		}
		if err := rejectImageKeys(ps); err != nil {
			return nil, nil, nil, nil, err
		}
		p, err := loadPane(ps)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if *p != (theme.Pane{}) {
			if panes == nil {
				panes = map[string]*theme.Pane{}
			}
			panes[name] = p
		}
		unknown = append(unknown, ps.Unknown("bg", "dim", "blur", "position")...)
	}
	return colors, nick, panes, unknown, nil
}

// loadVariants decodes theme.variants: only the base that isn't the
// theme's; a variant for the theme's own base is dropped (reported with
// the unknown keys). An empty variant ({}) is kept: Boson's built-in of
// that base with the shared settings.
func loadVariants(ts *configfile.Section, base string) (map[string]*theme.Variant, []string, error) {
	vs, err := ts.Sub("variants")
	if err != nil {
		return nil, nil, err
	}
	var out map[string]*theme.Variant
	var unknown []string
	for _, name := range vs.Keys() {
		if !theme.ValidBase(name) || name == base {
			unknown = append(unknown, vs.Path()+"."+name)
			continue
		}
		s, err := vs.Sub(name)
		if err != nil {
			return nil, nil, err
		}
		if s == nil {
			continue // null
		}
		v := &theme.Variant{}
		var u []string
		if v.Colors, v.Nick, v.Panes, u, err = loadLook(s); err != nil {
			return nil, nil, err
		}
		unknown = append(unknown, u...)
		unknown = append(unknown, s.Unknown("colors", "nick", "panes")...)
		if out == nil {
			out = map[string]*theme.Variant{}
		}
		out[name] = v
	}
	return out, unknown, nil
}

func loadPane(ps *configfile.Section) (*theme.Pane, error) {
	p := &theme.Pane{}
	if err := stringKey(ps, "bg", &p.BG, checkColor); err != nil {
		return nil, err
	}
	p.BG = strings.ToLower(p.BG)
	if err := stringKey(ps, "position", &p.Position, func(v string) string {
		if !theme.ValidPosition(v) {
			return fmt.Sprintf("must be one of %s, got %q", strings.Join(theme.Positions, ", "), v)
		}
		return ""
	}); err != nil {
		return nil, err
	}
	for key, spec := range map[string]struct {
		dst   **float64
		check func(float64) string
	}{"dim": {&p.Dim, theme.CheckDim}, "blur": {&p.Blur, theme.CheckBlur}} {
		v, err := ps.Float(key)
		if err != nil {
			return nil, err
		}
		if v != nil {
			if msg := spec.check(*v); msg != "" {
				return nil, ps.Errorf(key, "%s", msg)
			}
			*spec.dst = v
		}
	}
	return p, nil
}

// loadEmail decodes auth.email; nil when absent.
func loadEmail(auth *configfile.Section) (*EmailConfig, []string, error) {
	sec, err := auth.Sub("email")
	if err != nil || sec == nil {
		return nil, nil, err
	}
	e := &EmailConfig{}
	if err := stringKey(sec, "sender_name", &e.SenderName, CheckSenderName); err != nil {
		return nil, nil, err
	}
	e.SenderName = strings.TrimSpace(e.SenderName)
	if err := stringKey(sec, "accent", &e.Accent, CheckAccent); err != nil {
		return nil, nil, err
	}
	e.Accent = strings.ToLower(e.Accent)
	if err := stringKey(sec, "footer", &e.Footer, CheckFooter); err != nil {
		return nil, nil, err
	}
	e.Footer = strings.TrimSpace(e.Footer)
	logo, err := sec.Bool("logo")
	if err != nil {
		return nil, nil, err
	}
	if logo != nil {
		e.Logo = *logo
	}
	var unknown []string
	if ls, err := sec.Sub("layout"); err != nil {
		return nil, nil, err
	} else if ls != nil {
		if e.Layout, err = loadEmailFiles(ls, ls.Path()); err != nil {
			return nil, nil, err
		}
		unknown = append(unknown, ls.Unknown("mjml", "html")...)
	}
	tpls, err := sec.Sub("templates")
	if err != nil {
		return nil, nil, err
	}
	for _, name := range tpls.Keys() {
		if !slices.Contains(EmailTemplates, name) {
			unknown = append(unknown, tpls.Path()+"."+name)
			continue
		}
		ts, err := tpls.Sub(name)
		if err != nil {
			return nil, nil, err
		}
		if ts == nil {
			continue
		}
		var tpl EmailTemplate
		for key, spec := range map[string]struct {
			dst   **string
			check func(string) string
		}{"subject": {&tpl.Subject, CheckSubject}, "body": {&tpl.Body, CheckBody}} {
			var v string
			if err := stringKey(ts, key, &v, spec.check); err != nil {
				return nil, nil, err
			}
			if ts.Has(key) {
				*spec.dst = &v
			}
		}
		if tpl.Files, err = loadEmailFiles(ts, ts.Path()); err != nil {
			return nil, nil, err
		}
		if tpl.Subject != nil || tpl.Body != nil || tpl.Files != nil {
			if e.Templates == nil {
				e.Templates = map[string]EmailTemplate{}
			}
			e.Templates[name] = tpl
		}
		unknown = append(unknown, ts.Unknown("subject", "body", "mjml", "html")...)
	}
	unknown = append(unknown, sec.Unknown("sender_name", "accent", "footer", "logo", "templates", "layout")...)
	return e, unknown, nil
}

// flattenBranding adds the branding / email keys to an audit flat map.
func (f FileConfig) flattenBranding(m map[string]any) {
	if b := f.Branding; b != nil {
		m[KeyBrandingTheme] = b.Theme
		for _, img := range b.Images {
			m[KeyBrandingImage+img.Slot] = img.File
		}
	}
	if e := f.Email; e != nil {
		m[KeyEmail+"sender_name"] = e.SenderName
		m[KeyEmail+"accent"] = e.Accent
		m[KeyEmail+"footer"] = e.Footer
		m[KeyEmail+"logo"] = e.Logo
		files := func(prefix string, f *EmailFiles) {
			if f != nil {
				m[prefix+".html"] = f.HTML
				if f.MJML != "" {
					m[prefix+".mjml"] = f.MJML
				}
			}
		}
		files(KeyEmail+"layout", e.Layout)
		for name, t := range e.Templates {
			files(KeyEmail+"templates."+name, t.Files)
			if t.Subject != nil {
				m[KeyEmail+"templates."+name+".subject"] = *t.Subject
			}
			if t.Body != nil {
				m[KeyEmail+"templates."+name+".body"] = *t.Body
			}
		}
	}
}
