package theme

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"strings"
	"testing"
)

func pngBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, w, h))); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A 1×1 lossy WebP.
var webp1x1, _ = base64.StdEncoding.DecodeString("UklGRiQAAABXRUJQVlA4IBgAAAAwAQCdASoBAAEAAwA0JaQAA3AA/vuUAAA=")

func TestValidColor(t *testing.T) {
	for c, ok := range map[string]bool{
		"#7c3aed": true, "#ABCDEF": true, "#000000": true,
		"#fff": false, "7c3aed": false, "#7c3aedff": false, "#7c3aeg": false, "red": false, "": false, " #7c3aed": false,
	} {
		if ValidColor(c) != ok {
			t.Errorf("ValidColor(%q) = %v", c, !ok)
		}
	}
}

func TestRanges(t *testing.T) {
	if CheckDim(0) != "" || CheckDim(1) != "" || CheckDim(0.6) != "" || CheckDim(-0.1) == "" || CheckDim(1.01) == "" {
		t.Fatal("dim is 0..1")
	}
	if CheckBlur(0) != "" || CheckBlur(24) != "" || CheckBlur(24.5) == "" || CheckBlur(-1) == "" {
		t.Fatal("blur is 0..24")
	}
	if CheckRadius(0) != "" || CheckRadius(12) != "" || CheckRadius(13) == "" || CheckRadius(-1) == "" {
		t.Fatal("radius is 0..12")
	}
	if CheckNickPercent(100) != "" || CheckNickPercent(101) == "" {
		t.Fatal("nick is 0..100")
	}
	if !ValidPosition("center") || ValidPosition("middle") || !ValidPane("messages") || ValidPane("sidebar") {
		t.Fatal("enums")
	}
	if !ValidToken("accent-on") || ValidToken("accent_on") || len(Tokens) != 17 {
		t.Fatal("tokens must match the client's THEME_TOKENS")
	}
}

func TestCheckFileName(t *testing.T) {
	for _, bad := range []string{
		"", "../logo.png", "..png", "a/../b.png", "/etc/passwd", "dir/logo.png", `a\b.png`, ".hidden.png",
		"logo", "logo.exe", "logo.svgz", "logo.png ", "lo go.png", "logo..png", strings.Repeat("a", 130) + ".png", "logo.png\x00.svg",
	} {
		if _, err := CheckFileName(bad); err == nil {
			t.Errorf("CheckFileName(%q) accepted", bad)
		}
	}
	for name, mt := range map[string]string{
		"logo.svg": "image/svg+xml", "logo-ab12.webp": "image/webp", "Login_BG.JPG": "image/jpeg", "a.jpeg": "image/jpeg",
		"x.png": "image/png", "y.gif": "image/gif",
	} {
		got, err := CheckFileName(name)
		if err != nil || got != mt {
			t.Errorf("CheckFileName(%q) = %q, %v", name, got, err)
		}
	}
}

func TestCheckImage(t *testing.T) {
	ok := map[string][]byte{
		"image/png":     pngBytes(t, 4, 4),
		"image/webp":    webp1x1,
		"image/svg+xml": []byte(`<?xml version="1.0"?><!-- c --><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>`),
	}
	for mt, data := range ok {
		if err := CheckImage(mt, data); err != nil {
			t.Errorf("%s: %v", mt, err)
		}
	}
	bad := []struct {
		name, mt string
		data     []byte
		want     string
	}{
		{"empty", "image/png", nil, "empty"},
		{"png named webp", "image/webp", pngBytes(t, 2, 2), "extension says webp"},
		{"html named png", "image/png", []byte("<html><script>alert(1)</script></html>"), "not a valid image"},
		{"too wide", "image/png", pngBytes(t, MaxImageSide+1, 1), "4096"},
		{"too big", "image/png", bytes.Repeat([]byte{0}, MaxImageBytes+1), "2 MB"},
		{"html named svg", "image/svg+xml", []byte("<html><body/></html>"), "not an SVG"},
		{"text named svg", "image/svg+xml", []byte("hello <svg/>"), "not an SVG"},
		{"broken svg", "image/svg+xml", []byte("<svg"), "not an SVG"},
	}
	for _, c := range bad {
		err := CheckImage(c.mt, c.data)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

func TestDocumentJSONOmitsUnset(t *testing.T) {
	th := Theme{Version: Version, Base: BaseDark}
	if err := th.SetImage(PaneImageSlot("messages"), "https://x/m.webp"); err != nil {
		t.Fatal(err)
	}
	if err := th.SetImage("panes.sidebar.image", "x"); err == nil {
		t.Fatal("unknown slot accepted")
	}
	b, _ := json.Marshal(th)
	if string(b) != `{"version":1,"base":"dark","panes":{"messages":{"image":"https://x/m.webp"}}}` {
		t.Fatal(string(b))
	}
	c := th.Clone()
	c.Panes["messages"].Image = "changed"
	if th.Panes["messages"].Image != "https://x/m.webp" {
		t.Fatal("Clone must deep-copy panes")
	}
}
