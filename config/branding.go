package config

import (
	"fmt"
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
//	  images:                       # files in <config dir>/branding/
//	    logo: logo.svg
//	    login_background: login.webp
//	    panes.messages.image: messages.webp
//	auth:
//	  email:
//	    sender_name: "Example Chat"
//	    accent: "#7c3aed"
//	    footer: "Example Chat · example.com"
//	    logo: true
//	    templates:
//	      verification: { subject: "…", body: "…" }

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
}

// EmailTemplate overrides one email's wording; nil = Boson's default.
type EmailTemplate struct {
	Subject *string `json:"subject,omitempty"`
	Body    *string `json:"body,omitempty"`
}

// Config keys.
const (
	KeyBrandingTheme = "branding.theme"
	KeyBrandingImage = "branding.images." // + slot
	KeyEmail         = "auth.email."      // + field / templates.<name>.subject|body
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
		colors, err := ts.Sub("colors")
		if err != nil {
			return nil, nil, err
		}
		for _, k := range colors.Keys() {
			if !theme.ValidToken(k) {
				unknown = append(unknown, colors.Path()+"."+k)
				continue
			}
			var c string
			if err := stringKey(colors, k, &c, checkColor); err != nil {
				return nil, nil, err
			}
			if c == "" {
				continue // null
			}
			if t.Colors == nil {
				t.Colors = map[string]string{}
			}
			t.Colors[k] = strings.ToLower(c)
		}
		nick, err := ts.Sub("nick")
		if err != nil {
			return nil, nil, err
		}
		if nick != nil {
			n := &theme.Nick{}
			for key, dst := range map[string]**int{"saturation": &n.Saturation, "lightness": &n.Lightness} {
				v, err := nick.Int(key)
				if err != nil {
					return nil, nil, err
				}
				if v != nil {
					if msg := theme.CheckNickPercent(*v); msg != "" {
						return nil, nil, nick.Errorf(key, "%s", msg)
					}
					*dst = v
				}
			}
			if n.Saturation != nil || n.Lightness != nil {
				t.Nick = n
			}
			unknown = append(unknown, nick.Unknown("saturation", "lightness")...)
		}
		panes, err := ts.Sub("panes")
		if err != nil {
			return nil, nil, err
		}
		for _, name := range panes.Keys() {
			if !theme.ValidPane(name) {
				unknown = append(unknown, panes.Path()+"."+name)
				continue
			}
			ps, err := panes.Sub(name)
			if err != nil {
				return nil, nil, err
			}
			if ps == nil {
				continue
			}
			if err := rejectImageKeys(ps); err != nil {
				return nil, nil, err
			}
			p, err := loadPane(ps)
			if err != nil {
				return nil, nil, err
			}
			if *p != (theme.Pane{}) {
				if t.Panes == nil {
					t.Panes = map[string]*theme.Pane{}
				}
				t.Panes[name] = p
			}
			unknown = append(unknown, ps.Unknown("bg", "dim", "blur", "position")...)
		}
		unknown = append(unknown, ts.Unknown("version", "base", "colors", "nick", "radius", "font", "panes")...)
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
		n := imgs.Node(slot)
		b.Images = append(b.Images, BrandingImage{Slot: slot, File: file, Line: n.Line, Column: n.Column})
	}
	slices.SortFunc(b.Images, func(a, b BrandingImage) int { return strings.Compare(a.Slot, b.Slot) })
	unknown = append(unknown, sec.Unknown("theme", "images")...)
	return b, unknown, nil
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
		if tpl.Subject != nil || tpl.Body != nil {
			if e.Templates == nil {
				e.Templates = map[string]EmailTemplate{}
			}
			e.Templates[name] = tpl
		}
		unknown = append(unknown, ts.Unknown("subject", "body")...)
	}
	unknown = append(unknown, sec.Unknown("sender_name", "accent", "footer", "logo", "templates")...)
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
		for name, t := range e.Templates {
			if t.Subject != nil {
				m[KeyEmail+"templates."+name+".subject"] = *t.Subject
			}
			if t.Body != nil {
				m[KeyEmail+"templates."+name+".body"] = *t.Body
			}
		}
	}
}
