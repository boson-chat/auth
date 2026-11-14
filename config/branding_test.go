package config

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/boson-chat/auth/internal/configfile"
)

const brandingFile = `version: 1
branding:
  theme:
    version: 1
    base: light
    colors: { accent: "#7C3AED", bg: "#0b0b10", not-a-token: "#000000" }
    nick: { saturation: 62, lightness: 64 }
    radius: 2
    font: system
    sparkle: true
    panes:
      servers: { bg: "#0b0b10" }
      channels: { bg: "#111118", dim: 0.6, blur: 0 }
      messages: { dim: 0.7, blur: 8, position: center, glow: 1 }
      sidebar: { bg: "#111118" }
  images:
    logo: logo.svg
    panes.messages.image: messages.webp
    login_background: login.webp
auth:
  email:
    sender_name: "Example Chat"
    accent: "#7C3AED"
    footer: "Example Chat · example.com"
    logo: true
    templates:
      verification: { subject: "Confirm your {{network}} account", body: "Hi {{username}},\n\nConfirm: {{link}}" }
      invite: { subject: "Join us" }
      welcome: { subject: "x" }
`

func TestLoadBrandingAndEmail(t *testing.T) {
	f, err := loadFile(t, brandingFile)
	if err != nil {
		t.Fatal(err)
	}
	b := f.Branding
	if b == nil {
		t.Fatal("branding missing")
	}
	got, _ := json.Marshal(b.Theme)
	want := `{"version":1,"base":"light","colors":{"accent":"#7c3aed","bg":"#0b0b10"},"nick":{"saturation":62,"lightness":64},` +
		`"radius":2,"font":"system","panes":{"channels":{"bg":"#111118","dim":0.6,"blur":0},"messages":{"dim":0.7,"blur":8,"position":"center"},` +
		`"servers":{"bg":"#0b0b10"}}}`
	if string(got) != want {
		t.Fatalf("theme\n got %s\nwant %s", got, want)
	}
	var slots []string
	for _, img := range b.Images {
		slots = append(slots, img.Slot+"="+img.File)
		if img.Line == 0 || img.Column == 0 {
			t.Fatal("image entries carry their position")
		}
	}
	if strings.Join(slots, ",") != "login_background=login.webp,logo=logo.svg,panes.messages.image=messages.webp" {
		t.Fatal(slots)
	}
	e := f.Email
	if e == nil || e.SenderName != "Example Chat" || e.Accent != "#7c3aed" || !e.Logo || e.Footer != "Example Chat · example.com" {
		t.Fatalf("%+v", e)
	}
	v := e.Templates[EmailVerification]
	if *v.Subject != "Confirm your {{network}} account" || *v.Body != "Hi {{username}},\n\nConfirm: {{link}}" {
		t.Fatalf("%+v", v)
	}
	if inv := e.Templates[EmailInvite]; inv.Body != nil || *inv.Subject != "Join us" {
		t.Fatalf("%+v", inv)
	}
	// Unknown keys are dropped (and reported for the log).
	for _, k := range []string{"branding.theme.colors.not-a-token", "branding.theme.sparkle", "branding.theme.panes.messages.glow",
		"branding.theme.panes.sidebar", "auth.email.templates.welcome"} {
		if !slices.Contains(f.Unknown, k) {
			t.Errorf("unknown %s not reported: %v", k, f.Unknown)
		}
	}
	flat := f.Flatten()
	for _, k := range []string{"branding.theme", "branding.images.logo", "auth.email.accent", "auth.email.templates.verification.body", "auth.email.templates.invite.subject"} {
		if _, ok := flat[k]; !ok {
			t.Errorf("Flatten misses %s", k)
		}
	}
	if _, ok := flat["auth.email.templates.invite.body"]; ok {
		t.Error("unset template body must not be flattened")
	}
}

func TestBrandingAbsentAndEmpty(t *testing.T) {
	f, err := loadFile(t, "version: 1\nauth: { registration: open }\n")
	if err != nil || f.Branding != nil || f.Email != nil {
		t.Fatalf("absent sections must stay nil: %+v %v", f, err)
	}
	f, err = loadFile(t, "version: 1\nbranding: {}\nauth:\n  email: {}\n")
	if err != nil {
		t.Fatal(err)
	}
	if f.Branding == nil || f.Branding.Theme.Base != "dark" || f.Branding.Theme.Version != 1 || f.Email == nil || f.Email.Logo {
		t.Fatalf("empty sections are present with defaults: %+v %+v", f.Branding, f.Email)
	}
}

func TestBrandingValidationErrors(t *testing.T) {
	cases := []struct {
		name, src string
		line, col int
		want      string
	}{
		{"short colour", "branding:\n  theme:\n    colors: { accent: \"#fff\" }\n", 3, 23, "#rrggbb"},
		{"named colour", "branding:\n  theme:\n    colors:\n      bg: red\n", 4, 11, "#rrggbb"},
		{"base", "branding:\n  theme: { base: dim }\n", 2, 18, "dark or light"},
		{"font", "branding:\n  theme: { font: comic }\n", 2, 18, "boson or system"},
		{"radius", "branding:\n  theme: { radius: 13 }\n", 2, 20, "between 0 and 12"},
		{"radius type", "branding:\n  theme: { radius: big }\n", 2, 20, "integer"},
		{"nick", "branding:\n  theme:\n    nick: { saturation: 101 }\n", 3, 25, "between 0 and 100"},
		{"version", "branding:\n  theme: { version: 2 }\n", 2, 21, "must be 1"},
		{"dim", "branding:\n  theme:\n    panes:\n      messages: { dim: 1.5 }\n", 4, 24, "between 0 and 1"},
		{"blur", "branding:\n  theme:\n    panes:\n      messages: { blur: 25 }\n", 4, 25, "between 0 and 24"},
		{"position", "branding:\n  theme:\n    panes:\n      messages: { position: middle }\n", 4, 29, "center, top, bottom, left, right"},
		{"pane bg", "branding:\n  theme:\n    panes:\n      members: { bg: \"#12345\" }\n", 4, 22, "#rrggbb"},
		{"pane image url", "branding:\n  theme:\n    panes:\n      messages: { image: \"https://x/a.png\" }\n", 4, 26, "branding.images"},
		{"logo url", "branding:\n  theme:\n    logo: https://x/logo.png\n", 3, 11, "branding.images"},
		{"unknown slot", "branding:\n  images:\n    favicon: f.png\n", 3, 5, "unknown image slot"},
		{"traversal", "branding:\n  images:\n    logo: ../../etc/passwd.png\n", 3, 11, "plain file name"},
		{"absolute", "branding:\n  images:\n    logo: /etc/logo.png\n", 3, 11, "plain file name"},
		{"subdir", "branding:\n  images:\n    logo: sub/logo.png\n", 3, 11, "plain file name"},
		{"extension", "branding:\n  images:\n    logo: logo.html\n", 3, 11, ".png, .jpg"},
		{"image list", "branding:\n  images:\n    logo: [a.png]\n", 3, 11, "string"},
		{"theme not mapping", "branding:\n  theme: dark\n", 2, 10, "must be a mapping"},
		{"email accent", "auth:\n  email: { accent: purple }\n", 2, 20, "#rrggbb"},
		{"sender newline", "auth:\n  email: { sender_name: \"a\\nb\" }\n", 2, 25, "one line"},
		{"sender long", "auth:\n  email: { sender_name: " + strings.Repeat("a", 101) + " }\n", 2, 25, "at most 100"},
		{"logo type", "auth:\n  email: { logo: yes please }\n", 2, 18, "true or false"},
		{"subject newline", "auth:\n  email:\n    templates:\n      verification: { subject: \"a\\nb\" }\n", 4, 32, "one line"},
		{"empty body", "auth:\n  email:\n    templates:\n      password_reset: { body: \"  \" }\n", 4, 31, "can't be empty"},
		{"long body", "auth:\n  email:\n    templates:\n      invite: { body: " + strings.Repeat("a", MaxBodyLen+1) + " }\n", 4, 23, "at most"},
		{"control char", "auth:\n  email:\n    templates:\n      invite: { body: \"a\\u0007b\" }\n", 4, 23, "control"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadFile(t, c.src)
			e, ok := configfile.AsError(err)
			if !ok || !strings.Contains(e.Msg, c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if e.Line != c.line || e.Column != c.col {
				t.Fatalf("position %d:%d, want %d:%d (%v)", e.Line, e.Column, c.line, c.col, e)
			}
		})
	}
}

func TestNullKeysAreAbsent(t *testing.T) {
	f, err := loadFile(t, "branding:\n  theme:\n    radius: ~\n    colors: { accent: ~ }\n  images:\n    logo: ~\nauth:\n  email:\n    accent: ~\n    templates:\n      verification: { subject: ~ }\n")
	if err != nil {
		t.Fatal(err)
	}
	if f.Branding.Theme.Radius != nil || f.Branding.Theme.Colors != nil || len(f.Branding.Images) != 0 {
		t.Fatalf("%+v", f.Branding)
	}
	if f.Email.Accent != "" || f.Email.Templates != nil {
		t.Fatalf("%+v", f.Email)
	}
}
