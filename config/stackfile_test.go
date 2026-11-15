package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/boson-chat/auth/internal/configfile"
	"gopkg.in/yaml.v3"
)

func loadFile(t *testing.T, src string) (FileConfig, error) {
	t.Helper()
	doc, err := configfile.Parse([]byte(src))
	if err != nil {
		return FileConfig{}, err
	}
	return LoadFileConfig(doc)
}

const fullFile = `version: 1
network:
  name: Example
auth:
  registration: invite
  require_email_verification: false
  guest_access: false
  channel_creation: admins
  voice_channel_creation: registered
  channel_auto_register: false
  channel_expiry_days: 30
  cors_allowed_origins: [https://a.example.com/, "http://localhost:5173"]
  smtp: { host: smtp.example.com, port: 465, from: "Example <hi@example.com>", tls: tls }
irc:
  plaintext: true   # another service's section: ignored
voice: { rooms: [{ id: general }] }
`

func TestLoadFileConfigFull(t *testing.T) {
	f, err := loadFile(t, fullFile)
	if err != nil {
		t.Fatal(err)
	}
	if *f.NetworkName != "Example" || *f.Registration != "invite" || *f.RequireEmailVerification || *f.GuestAccess ||
		*f.ChannelCreation != "admins" || *f.VoiceChannelCreation != "registered" || *f.ChannelAutoRegister || *f.ChannelExpiryDays != 30 {
		t.Fatalf("%+v", f)
	}
	if !f.CORSAllowedOriginsSet || strings.Join(f.CORSAllowedOrigins, ",") != "https://a.example.com,http://localhost:5173" {
		t.Fatal(f.CORSAllowedOrigins)
	}
	if *f.SMTPHost != "smtp.example.com" || *f.SMTPPort != 465 || *f.SMTPFrom != "Example <hi@example.com>" || *f.SMTPTLS != "tls" {
		t.Fatalf("%+v", f)
	}
	if len(f.Unknown) != 0 {
		t.Fatal(f.Unknown)
	}
}

func TestLoadFileConfigAbsentKeys(t *testing.T) {
	for _, src := range []string{"", "version: 1\n", "version: 1\nauth:\n", "auth: {}\nnetwork: ~\n"} {
		f, err := loadFile(t, src)
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}
		if len(f.Flatten()) != 0 {
			t.Fatalf("%q: %v", src, f.Flatten())
		}
	}
	// An explicit empty list is a value (no CORS origins), not "absent".
	f, err := loadFile(t, "auth:\n  cors_allowed_origins: []\n  smtp: {}\n")
	if err != nil || !f.CORSAllowedOriginsSet || len(f.CORSAllowedOrigins) != 0 {
		t.Fatal(f, err)
	}
}

func TestLoadFileConfigValidation(t *testing.T) {
	cases := []struct {
		src       string
		line, col int
		msg       string
	}{
		{"auth:\n  registration: sometimes\n", 2, 17, "open, invite or closed"},
		{"auth:\n  channel_creation: everyone\n", 2, 21, "registered or admins"},
		{"auth:\n  voice_channel_creation: all\n", 2, 27, "admins, founders or registered"},
		{"auth:\n  channel_expiry_days: 4000\n", 2, 24, "between 0 and 3650"},
		{"auth:\n  channel_expiry_days: soon\n", 2, 24, "integer"},
		{"auth:\n  guest_access: yes\n", 2, 17, "true or false"},
		{"auth:\n  cors_allowed_origins:\n    - https://ok.example.com\n    - https://bad.example.com/path\n", 4, 7, "not an origin"},
		{"auth:\n  cors_allowed_origins: {a: b}\n", 2, 25, "list of strings"},
		{"auth:\n  smtp:\n    port: 70000\n", 3, 11, "between 1 and 65535"},
		{"auth:\n  smtp:\n    tls: maybe\n", 3, 10, "starttls, tls or none"},
		{"auth:\n  smtp:\n    from: not an address\n", 3, 11, "email address"},
		{"auth:\n  smtp:\n    password: hunter2\n", 3, 15, "secrets"},
		{"auth:\n  smtp: plain\n", 2, 9, "auth.smtp must be a mapping"},
		{"network:\n  name: \"\"\n", 2, 9, "can't be empty"},
		{"version: 3\n", 1, 10, "version must be 1"},
	}
	for _, c := range cases {
		_, err := loadFile(t, c.src)
		e, ok := configfile.AsError(err)
		if !ok {
			t.Fatalf("%q: want positioned error, got %v", c.src, err)
		}
		if e.Line != c.line || e.Column != c.col || !strings.Contains(e.Msg, c.msg) {
			t.Errorf("%q: got %d:%d %q, want %d:%d …%s…", c.src, e.Line, e.Column, e.Msg, c.line, c.col, c.msg)
		}
	}
}

func TestLoadFileConfigUnknownKeys(t *testing.T) {
	f, err := loadFile(t, "network: { name: X, motd: hi }\nauth:\n  registraton: open\n  smtp: { hots: x }\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.Unknown, ",") != "network.motd,auth.registraton,auth.smtp.hots" {
		t.Fatal(f.Unknown)
	}
}

func envConfig() Config {
	var c Config
	c.AppConfig.SiteName = "env-site"
	c.AccountConfig = AccountConfig{Registration: "open", RequireEmailVerification: true, ChannelCreation: "registered",
		VoiceChannelCreation: "founders", ChannelAutoRegister: true, GuestAccess: true, ChannelExpiryDays: 7}
	c.HTTPConfig.CORSAllowedOrigins = "https://env.example.com"
	c.SMTPConfig = SMTPConfig{Host: "env-smtp", Port: 587, User: "u", Password: "p", From: "env <e@example.com>", TLS: "starttls"}
	return c
}

func TestWithFilePrecedence(t *testing.T) {
	env := envConfig()
	// Nothing in the file: env values everywhere.
	if got := env.WithFile(FileConfig{}); got.AccountConfig != env.AccountConfig || got.SMTPConfig != env.SMTPConfig ||
		got.AppConfig.SiteName != "env-site" || got.HTTPConfig.CORSAllowedOrigins != env.HTTPConfig.CORSAllowedOrigins {
		t.Fatalf("%+v", got)
	}
	f, err := loadFile(t, "network: { name: File }\nauth:\n  registration: closed\n  guest_access: false\n  channel_expiry_days: 0\n  cors_allowed_origins: []\n  smtp: { port: 2525 }\n")
	if err != nil {
		t.Fatal(err)
	}
	got := env.WithFile(f)
	a := got.AccountConfig
	if got.AppConfig.SiteName != "File" || a.Registration != "closed" || a.GuestAccess || a.ChannelExpiryDays != 0 {
		t.Fatalf("file values must win: %+v", got)
	}
	// Keys not in the file keep their env value.
	if !a.RequireEmailVerification || a.VoiceChannelCreation != "founders" || got.SMTPConfig.Host != "env-smtp" || got.SMTPConfig.TLS != "starttls" {
		t.Fatalf("env must fill absent keys: %+v", got)
	}
	// Secrets always come from env.
	if got.SMTPConfig.Port != 2525 || got.SMTPConfig.User != "u" || got.SMTPConfig.Password != "p" {
		t.Fatalf("%+v", got.SMTPConfig)
	}
	if got.HTTPConfig.CORSAllowedOrigins != "" {
		t.Fatal("an empty list in the file means no origins", got.HTTPConfig.CORSAllowedOrigins)
	}
	// The env config itself is untouched.
	if env.AccountConfig.Registration != "open" {
		t.Fatal("WithFile must not modify its receiver")
	}
}

func TestExportFileRoundTrip(t *testing.T) {
	env := envConfig()
	out, err := ExportFile(env, true)
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := yaml.Unmarshal(out, &probe); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(string(out), "password") || strings.Contains(string(out), "user:") {
		t.Fatalf("secrets must not be exported:\n%s", out)
	}
	f, err := loadFile(t, "version: 1\n"+string(out))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := (Config{}).WithFile(f); got.AccountConfig.Registration != "open" || got.AccountConfig.ChannelExpiryDays != 7 ||
		got.AppConfig.SiteName != "env-site" || got.SMTPConfig.Host != "env-smtp" || got.HTTPConfig.CORSAllowedOrigins != "https://env.example.com" {
		t.Fatalf("round trip: %+v\n%s", got, out)
	}
	// CORS left to its APP_URL default when not set explicitly.
	out, _ = ExportFile(env, false)
	if strings.Contains(string(out), "cors_allowed_origins") {
		t.Fatalf("%s", out)
	}
}

func TestFilesEnabledFromFile(t *testing.T) {
	env := envConfig()
	env.FilesConfig = FilesConfig{PublicURL: "https://files.example.com/"}
	if u := env.FilesConfig.URL(); u != "" {
		t.Fatalf("off by default: %q", u)
	}
	// files: belongs to the files service: auth only reads enabled and
	// doesn't report the other keys as unknown.
	f, err := loadFile(t, "files:\n  enabled: true\n  retention: 72h\n  account: { quota: 5GB, max_file: 100MB }\n")
	if err != nil {
		t.Fatal(err)
	}
	if f.FilesEnabled == nil || !*f.FilesEnabled || len(f.Unknown) != 0 {
		t.Fatalf("%+v", f)
	}
	if got := env.WithFile(f).FilesConfig.URL(); got != "https://files.example.com" {
		t.Fatalf("files_url = %q", got)
	}
	if m := f.Flatten(); m[KeyFilesEnabled] != true {
		t.Fatal(m)
	}
	// enabled: false in the file wins over FILES_ENABLED=true.
	env.FilesConfig.Enabled = true
	f, err = loadFile(t, "files: { enabled: false }\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := env.WithFile(f).FilesConfig.URL(); got != "" {
		t.Fatalf("files_url = %q", got)
	}
	// Absent: the env value.
	if got := env.WithFile(FileConfig{}).FilesConfig.URL(); got != "https://files.example.com" {
		t.Fatalf("files_url = %q", got)
	}
	if _, err := loadFile(t, "files: { enabled: maybe }\n"); err == nil || !strings.Contains(err.Error(), "files.enabled") {
		t.Fatalf("want a files.enabled error, got %v", err)
	}
}

func TestRoleChannelsFromFile(t *testing.T) {
	var env Config
	env.RolesConfig = RolesConfig{ChannelsAutojoin: false, ChannelsRejoin: RejoinLogin}
	f, err := loadFile(t, "roles:\n  channels:\n    autojoin: true\n    rejoin: once\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Unknown) != 0 {
		t.Fatalf("unknown %v", f.Unknown)
	}
	got := env.WithFile(f).RolesConfig
	if !got.ChannelsAutojoin || got.ChannelsRejoin != RejoinOnce {
		t.Fatalf("%+v", got)
	}
	if m := f.Flatten(); m[KeyRolesChannelsAutojoin] != true || m[KeyRolesChannelsRejoin] != "once" {
		t.Fatal(m)
	}
	// Absent: env / defaults (off, login).
	if got := env.WithFile(FileConfig{}).RolesConfig; got.ChannelsAutojoin || got.ChannelsRejoin != RejoinLogin {
		t.Fatalf("%+v", got)
	}
	f, err = loadFile(t, "roles:\n  channels: { autojoin: false }\n  other: 1\n")
	if err != nil {
		t.Fatal(err)
	}
	if f.RolesChannelsAutojoin == nil || *f.RolesChannelsAutojoin || f.RolesChannelsRejoin != nil || !slices.Contains(f.Unknown, "roles.other") {
		t.Fatalf("%+v", f)
	}
	for _, bad := range []string{"roles:\n  channels: { rejoin: always }\n", "roles:\n  channels: { autojoin: maybe }\n", "roles:\n  channels: []\n"} {
		if _, err := loadFile(t, bad); err == nil || !strings.Contains(err.Error(), "roles.channels") {
			t.Errorf("%q: want a roles.channels error, got %v", bad, err)
		}
	}
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.RolesConfig.ChannelsAutojoin || c.RolesConfig.ChannelsRejoin != RejoinLogin {
		t.Fatalf("defaults %+v", c.RolesConfig)
	}
	c.RolesConfig.ChannelsRejoin = "sometimes"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "ROLE_CHANNELS_REJOIN") {
		t.Fatalf("validate: %v", err)
	}
}
