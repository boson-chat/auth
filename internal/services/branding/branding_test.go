package branding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/configfile"
	"github.com/boson-chat/auth/internal/theme"
)

const pub = "https://auth.example.com"

var (
	svg     = []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect width="1" height="1"/></svg>`)
	webp, _ = base64.StdEncoding.DecodeString("UklGRiQAAABXRUJQVlA4IBgAAAAwAQCdASoBAAEAAwA0JaQAA3AA/vuUAAA=")
)

func pngBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 8, 8)))
	return buf.Bytes()
}

func hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:8])
}

func dirWith(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func cfg(images ...string) *config.BrandingConfig {
	b := &config.BrandingConfig{Theme: theme.Theme{Version: 1, Base: "dark", Colors: map[string]string{"accent": "#7c3aed"}}}
	for i := 0; i+1 < len(images); i += 2 {
		b.Images = append(b.Images, config.BrandingImage{Slot: images[i], File: images[i+1], Line: 10 + i, Column: 11})
	}
	return b
}

func TestPrepareRendersAbsoluteVersionedURLs(t *testing.T) {
	logoPNG := pngBytes(t)
	dir := dirWith(t, map[string][]byte{"logo.svg": svg, "wide.png": logoPNG, "msg.webp": webp, "unrelated.png": logoPNG})
	snap, err := Prepare(cfg("logo", "logo.svg", "logo_wide", "wide.png", "panes.messages.image", "msg.webp", "login_background", "msg.webp"), dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	s := NewBrandingService(pub)
	if _, ok := s.Document(context.Background()); ok || s.URL() != "" {
		t.Fatal("nothing configured yet")
	}
	s.Set(snap)
	doc, ok := s.Document(context.Background())
	if !ok {
		t.Fatal("document missing")
	}
	var got map[string]any
	if err := json.Unmarshal(doc.JSON, &got); err != nil {
		t.Fatal(err)
	}
	if got["logo"] != pub+"/v1/branding/assets/logo.svg?v="+hash(svg) ||
		got["logo_wide"] != pub+"/v1/branding/assets/wide.png?v="+hash(logoPNG) ||
		got["login_background"] != pub+"/v1/branding/assets/msg.webp?v="+hash(webp) {
		t.Fatalf("%s", doc.JSON)
	}
	if got["panes"].(map[string]any)["messages"].(map[string]any)["image"] != pub+"/v1/branding/assets/msg.webp?v="+hash(webp) {
		t.Fatalf("%s", doc.JSON)
	}
	if got["version"] != float64(1) || got["base"] != "dark" {
		t.Fatalf("%s", doc.JSON)
	}
	if !strings.HasPrefix(doc.ETag, `"`) || len(doc.ETag) < 10 {
		t.Fatal(doc.ETag)
	}
	if a, ok := s.Asset(context.Background(), "wide.png"); !ok || !bytes.Equal(a.Data, logoPNG) || a.MediaType != "image/png" || a.Hash != hash(logoPNG) {
		t.Fatal("asset", ok)
	}
	if _, ok := s.Asset(context.Background(), "unrelated.png"); ok {
		t.Fatal("only referenced files are served")
	}
	if s.URL() != pub+"/v1/branding" {
		t.Fatal(s.URL())
	}
	// Emails prefer the raster wordmark.
	if s.EmailLogoURL() != got["logo_wide"] {
		t.Fatal(s.EmailLogoURL())
	}
	// The input theme is not modified (it is the config's).
	c := cfg("logo", "logo.svg")
	if _, err := Prepare(c, dir, pub); err != nil || c.Theme.Logo != "" {
		t.Fatal("Prepare must not write into the config")
	}
	s.Set(nil)
	if _, ok := s.Document(context.Background()); ok || s.EmailLogoURL() != "" {
		t.Fatal("Set(nil) removes the branding")
	}
}

func TestETagFollowsContent(t *testing.T) {
	dir := dirWith(t, map[string][]byte{"a.svg": svg})
	a, _ := Prepare(cfg("logo", "a.svg"), dir, pub)
	b, _ := Prepare(cfg("logo", "a.svg"), dir, pub)
	if a.doc.ETag != b.doc.ETag {
		t.Fatal("same content, same ETag")
	}
	_ = os.WriteFile(filepath.Join(dir, "a.svg"), append([]byte(nil), bytes.Replace(svg, []byte(`width="1"`), []byte(`width="2"`), 1)...), 0o644)
	c, _ := Prepare(cfg("logo", "a.svg"), dir, pub)
	if c.doc.ETag == a.doc.ETag {
		t.Fatal("new image bytes → new ?v= → new ETag")
	}
}

func TestEmailLogoFallsBackToSVG(t *testing.T) {
	dir := dirWith(t, map[string][]byte{"logo.svg": svg, "wide.svg": svg})
	snap, _ := Prepare(cfg("logo", "logo.svg"), dir, pub)
	if !strings.Contains(snap.emailLogo.URL, "logo.svg") {
		t.Fatal(snap.emailLogo.URL)
	}
	snap, _ = Prepare(cfg("logo", "logo.svg", "logo_wide", "wide.svg"), dir, pub)
	if !strings.Contains(snap.emailLogo.URL, "wide.svg") {
		t.Fatal(snap.emailLogo.URL)
	}
	dir = dirWith(t, map[string][]byte{"logo.png": pngBytes(t), "wide.svg": svg})
	snap, _ = Prepare(cfg("logo", "logo.png", "logo_wide", "wide.svg"), dir, pub)
	if !strings.Contains(snap.emailLogo.URL, "logo.png") {
		t.Fatal("raster mark beats an SVG wordmark", snap.emailLogo.URL)
	}
	if snap.emailLogo.Width != 8 || snap.emailLogo.Height != 8 {
		t.Fatal("raster size", snap.emailLogo)
	}
	dir = dirWith(t, map[string][]byte{"logo.png": pngBytes(t), "wide.webp": webp})
	snap, _ = Prepare(cfg("logo", "logo.png", "logo_wide", "wide.webp"), dir, pub)
	if !strings.Contains(snap.emailLogo.URL, "logo.png") {
		t.Fatal("PNG mark beats a WebP wordmark (Outlook shows no WebP)", snap.emailLogo.URL)
	}
	snap, _ = Prepare(cfg("logo_wide", "wide.webp"), dir, pub)
	if !strings.Contains(snap.emailLogo.URL, "wide.webp") || snap.emailLogo.Width != 1 {
		t.Fatal("WebP when it is the only raster", snap.emailLogo)
	}
	snap, _ = Prepare(cfg("login_background", "logo.png"), dir, pub)
	if snap.emailLogo != (EmailLogo{}) {
		t.Fatal("no logo slot → no email logo")
	}
}

func TestPrepareErrorsPointAtTheFileName(t *testing.T) {
	big := append([]byte("<svg>"), bytes.Repeat([]byte(" "), theme.MaxImageBytes)...)
	big = append(big, []byte("</svg>")...)
	dir := dirWith(t, map[string][]byte{"fake.png": []byte("<html>"), "big.svg": big, "wrong.webp": pngBytes(t)})
	if err := os.Mkdir(filepath.Join(dir, "sub.png"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.png")
	_ = os.WriteFile(outside, pngBytes(t), 0o644)
	if err := os.Symlink(outside, filepath.Join(dir, "link.png")); err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]string{
		"missing.png": "not found",
		"fake.png":    "not a valid image",
		"big.svg":     "2 MB",
		"wrong.webp":  "extension says webp",
		"sub.png":     "not a regular file",
		"link.png":    "can't be read", // os.Root refuses a symlink out of the directory
	} {
		_, err := Prepare(cfg("logo", file), dir, pub)
		e, ok := configfile.AsError(err)
		if !ok || !strings.Contains(e.Msg, want) || !strings.Contains(e.Msg, "branding.images.logo: "+file) || e.Line != 10 || e.Column != 11 {
			t.Errorf("%s: %v, want %q at 10:11", file, err, want)
		}
	}
	if _, err := Prepare(cfg("logo", "x.png"), filepath.Join(dir, "nope"), pub); err == nil || !strings.Contains(err.Error(), "branding directory") {
		t.Fatal(err)
	}
	if snap, err := Prepare(nil, dir, pub); snap != nil || err != nil {
		t.Fatal("nil config → nil snapshot")
	}
	// Without images the directory need not exist.
	if _, err := Prepare(cfg(), filepath.Join(dir, "nope"), pub); err != nil {
		t.Fatal(err)
	}
}

func TestDocumentSizeLimit(t *testing.T) {
	dir := dirWith(t, map[string][]byte{"a.svg": svg})
	long := "https://auth.example.com/" + strings.Repeat("x", theme.MaxDocumentSize)
	if _, err := Prepare(cfg("logo", "a.svg"), dir, long); err == nil || !strings.Contains(err.Error(), "at most 16384") {
		t.Fatal(err)
	}
}

func TestPrepareVariants(t *testing.T) {
	dir := dirWith(t, map[string][]byte{"msg.webp": webp, "msg-light.svg": svg})
	plain := cfg("panes.messages.image", "msg.webp")
	before, err := Prepare(plain, dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	// A config without variants renders exactly as before: no variants key.
	if strings.Contains(string(before.doc.JSON), "variants") {
		t.Fatalf("%s", before.doc.JSON)
	}

	withVariant := func(accent string, images ...string) *config.BrandingConfig {
		c := cfg(append([]string{"panes.messages.image", "msg.webp"}, images...)...)
		dim := 0.3
		c.Theme.Variants = map[string]*theme.Variant{"light": {
			Colors: map[string]string{"accent": accent},
			Panes:  map[string]*theme.Pane{"messages": {Dim: &dim}},
		}}
		return c
	}
	in := withVariant("#6d28d9", "variants.light.panes.messages.image", "msg-light.svg")
	snap, err := Prepare(in, dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Panes    map[string]map[string]any `json:"panes"`
		Variants map[string]struct {
			Colors map[string]string         `json:"colors"`
			Panes  map[string]map[string]any `json:"panes"`
		} `json:"variants"`
	}
	if err := json.Unmarshal(snap.doc.JSON, &got); err != nil {
		t.Fatal(err)
	}
	light := got.Variants["light"]
	if light.Colors["accent"] != "#6d28d9" || light.Panes["messages"]["dim"] != 0.3 ||
		light.Panes["messages"]["image"] != pub+"/v1/branding/assets/msg-light.svg?v="+hash(svg) ||
		got.Panes["messages"]["image"] != pub+"/v1/branding/assets/msg.webp?v="+hash(webp) {
		t.Fatalf("%s", snap.doc.JSON)
	}
	if _, ok := snap.assets["msg-light.svg"]; !ok {
		t.Fatal("the variant's image is served")
	}
	if in.Theme.Variants["light"].Panes["messages"].Image != "" {
		t.Fatal("Prepare must not write into the config's variant")
	}
	// Without its own image the variant's pane has none: the client takes the primary's.
	noImg, _ := Prepare(withVariant("#6d28d9"), dir, pub)
	if strings.Contains(string(noImg.doc.JSON), "msg-light") {
		t.Fatalf("%s", noImg.doc.JSON)
	}

	// The ETag follows the variants.
	again, _ := Prepare(withVariant("#6d28d9", "variants.light.panes.messages.image", "msg-light.svg"), dir, pub)
	other, _ := Prepare(withVariant("#5b21b6", "variants.light.panes.messages.image", "msg-light.svg"), dir, pub)
	if again.doc.ETag != snap.doc.ETag {
		t.Fatal("same variants, same ETag")
	}
	for name, s := range map[string]*Snapshot{"no variant": before, "variant colour": other, "variant image": noImg} {
		if s.doc.ETag == snap.doc.ETag {
			t.Errorf("%s: ETag unchanged", name)
		}
	}
}
