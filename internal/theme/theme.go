// Package theme is the boson-theme/1 document: a network's colours, panes
// and images, shared by the stack (GET /v1/branding), the directory and the
// client. The rules here are the same everywhere: servers validate on
// write, the client again on read.
package theme

import (
	"fmt"
	"regexp"
	"slices"
)

// Version is the document version (boson-theme/1).
const Version = 1

// Limits of the format.
const (
	MaxRadius       = 12
	MaxBlur         = 24
	MaxNickPercent  = 100
	MaxImageBytes   = 2 << 20
	MaxImageSide    = 4096
	MaxDocumentSize = 16 << 10
)

// Bases.
const (
	BaseDark  = "dark"
	BaseLight = "light"
)

// Fonts.
const (
	FontBoson  = "boson"
	FontSystem = "system"
)

// Tokens are the themeable colour tokens (THEME_TOKENS in the client's
// theme.types.ts), in the editor's order.
var Tokens = []string{
	"bg", "surface", "surface-raised", "surface-hover", "border", "border-soft",
	"fg", "fg-2", "fg-3", "muted", "meta",
	"accent", "accent-on",
	"success", "warn", "danger", "info",
}

// Panes are the client's themeable panes.
var Panes = []string{"servers", "channels", "messages", "members"}

// Positions are the background-image anchors of a pane.
var Positions = []string{"center", "top", "bottom", "left", "right"}

// ImageExts are the accepted image file extensions (lower case) and their
// media types.
var ImageExts = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".webp": "image/webp",
	".gif":  "image/gif",
	".svg":  "image/svg+xml",
}

// Image slots of the document: logo, logo_wide, login_background and
// panes.<pane>.image.
const (
	SlotLogo            = "logo"
	SlotLogoWide        = "logo_wide"
	SlotLoginBackground = "login_background"
)

// PaneImageSlot is the slot of a pane's background image.
func PaneImageSlot(pane string) string { return "panes." + pane + ".image" }

// Slots lists every image slot.
func Slots() []string {
	out := []string{SlotLogo, SlotLogoWide, SlotLoginBackground}
	for _, p := range Panes {
		out = append(out, PaneImageSlot(p))
	}
	return out
}

var colorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// ValidColor reports whether c is #rrggbb.
func ValidColor(c string) bool { return colorRe.MatchString(c) }

// ValidToken reports whether k is a colour token.
func ValidToken(k string) bool { return slices.Contains(Tokens, k) }

// ValidPane reports whether p is a pane name.
func ValidPane(p string) bool { return slices.Contains(Panes, p) }

// ValidPosition reports whether p is a pane image position.
func ValidPosition(p string) bool { return slices.Contains(Positions, p) }

// ValidSlot reports whether s is an image slot.
func ValidSlot(s string) bool { return slices.Contains(Slots(), s) }

// Nick holds the per-nick colour saturation / lightness (percent).
type Nick struct {
	Saturation *int `json:"saturation,omitempty"`
	Lightness  *int `json:"lightness,omitempty"`
}

// Pane is one pane's background.
type Pane struct {
	BG       string   `json:"bg,omitempty"`
	Image    string   `json:"image,omitempty"`
	Dim      *float64 `json:"dim,omitempty"`
	Blur     *float64 `json:"blur,omitempty"`
	Position string   `json:"position,omitempty"`
}

// Theme is a boson-theme/1 document. Empty / nil fields are omitted.
type Theme struct {
	Version         int               `json:"version"`
	Base            string            `json:"base"`
	Colors          map[string]string `json:"colors,omitempty"`
	Nick            *Nick             `json:"nick,omitempty"`
	Radius          *int              `json:"radius,omitempty"`
	Font            string            `json:"font,omitempty"`
	Panes           map[string]*Pane  `json:"panes,omitempty"`
	Logo            string            `json:"logo,omitempty"`
	LogoWide        string            `json:"logo_wide,omitempty"`
	LoginBackground string            `json:"login_background,omitempty"`
}

// SetImage sets the URL of an image slot.
func (t *Theme) SetImage(slot, url string) error {
	switch slot {
	case SlotLogo:
		t.Logo = url
	case SlotLogoWide:
		t.LogoWide = url
	case SlotLoginBackground:
		t.LoginBackground = url
	default:
		for _, p := range Panes {
			if slot == PaneImageSlot(p) {
				if t.Panes == nil {
					t.Panes = map[string]*Pane{}
				}
				if t.Panes[p] == nil {
					t.Panes[p] = &Pane{}
				}
				t.Panes[p].Image = url
				return nil
			}
		}
		return fmt.Errorf("unknown image slot %q", slot)
	}
	return nil
}

// Clone returns a deep copy.
func (t Theme) Clone() Theme {
	c := t
	if t.Colors != nil {
		c.Colors = make(map[string]string, len(t.Colors))
		for k, v := range t.Colors {
			c.Colors[k] = v
		}
	}
	if t.Nick != nil {
		n := *t.Nick
		c.Nick = &n
	}
	if t.Panes != nil {
		c.Panes = make(map[string]*Pane, len(t.Panes))
		for k, v := range t.Panes {
			p := *v
			c.Panes[k] = &p
		}
	}
	return c
}

// Range checks shared by every reader of the format; each returns "" when
// v is fine, otherwise the reason.

func CheckDim(v float64) string {
	if v < 0 || v > 1 {
		return fmt.Sprintf("must be between 0 and 1, got %v", v)
	}
	return ""
}

func CheckBlur(v float64) string {
	if v < 0 || v > MaxBlur {
		return fmt.Sprintf("must be between 0 and %d (px), got %v", MaxBlur, v)
	}
	return ""
}

func CheckRadius(v int) string {
	if v < 0 || v > MaxRadius {
		return fmt.Sprintf("must be between 0 and %d, got %d", MaxRadius, v)
	}
	return ""
}

func CheckNickPercent(v int) string {
	if v < 0 || v > MaxNickPercent {
		return fmt.Sprintf("must be between 0 and %d, got %d", MaxNickPercent, v)
	}
	return ""
}
