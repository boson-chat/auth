package stackconfig

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	auditrepo "github.com/boson-chat/auth/internal/db/repositories/audit"
	"github.com/boson-chat/auth/internal/mailer"
	"github.com/boson-chat/auth/internal/services/branding"
	"github.com/boson-chat/auth/internal/services/settings"
	"github.com/boson-chat/auth/internal/services/sso"
)

type fakeSettings struct {
	settings.SettingsServiceImpl
	mu   sync.Mutex
	file *config.AccountConfig
	sets int
}

func (f *fakeSettings) SetFile(v *config.AccountConfig) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.file, f.sets = v, f.sets+1
}

type fakeEmail struct {
	name string
	cfg  *config.EmailConfig
}

func (f *fakeEmail) SetSiteName(n string)            { f.name = n }
func (f *fakeEmail) SetConfig(c *config.EmailConfig) { f.cfg = c }

type auditSpy struct {
	events []string
	metas  []map[string]any
}

func (a *auditSpy) Record(_ context.Context, _, event string, meta map[string]any) {
	a.events, a.metas = append(a.events, event), append(a.metas, meta)
}
func (a *auditSpy) RecordTarget(ctx context.Context, actor, _, event string, meta map[string]any) {
	a.Record(ctx, actor, event, meta)
}
func (a *auditSpy) List(context.Context, auditrepo.Filter) ([]*auditrepo.EntryView, error) {
	return nil, nil
}

type namedMailer struct{ host string }

func (namedMailer) Send(context.Context, mailer.Message) error { return nil }

type fixture struct {
	svc      *StackConfigService
	settings *fakeSettings
	email    *fakeEmail
	audit    *auditSpy
	mail     *mailer.Swappable
	returnTo *sso.ReturnToPolicy
	path     string
}

func envCfg(path string) config.Config {
	var c config.Config
	c.AppConfig.SiteName = "env-site"
	c.AppConfig.ConfigFile = path
	c.AppConfig.ConfigPoll = time.Hour
	c.AccountConfig = config.AccountConfig{Registration: "open", RequireEmailVerification: true, ChannelCreation: "registered",
		VoiceChannelCreation: "founders", ChannelAutoRegister: true, GuestAccess: true, AccountSetupTTL: time.Hour}
	c.HTTPConfig.AppURL, c.HTTPConfig.PublicURL = "https://app.example.com", "https://auth.example.com"
	c.HTTPConfig.CORSAllowedOrigins = "https://app.example.com"
	c.SMTPConfig = config.SMTPConfig{Host: "env-smtp", Port: 587, From: "env <e@example.com>", TLS: "starttls"}
	c.TokenConfig = config.TokenConfig{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Minute, VoiceTokenTTL: time.Minute,
		SessionMaxAge: time.Minute, KeyRotation: time.Minute}
	c.SSOConfig = config.SSOConfig{StateTTL: time.Minute, CodeTTL: time.Minute, HTTPTimeout: time.Minute}
	return c
}

func newFixture(t *testing.T, content string) *fixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "boson.yaml")
	if content != "" {
		write(t, path, content)
	}
	rt, err := sso.NewReturnToPolicy("https://app.example.com", []string{"https://app.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{settings: &fakeSettings{}, email: &fakeEmail{}, audit: &auditSpy{},
		mail: mailer.NewSwappable(namedMailer{host: "boot"}), returnTo: rt, path: path}
	f.svc = NewStackConfigService(Deps{
		Env: envCfg(path), Settings: f.settings, Email: f.email, Mailer: f.mail, ReturnTo: rt, Audit: f.audit,
		NewMailer: func(c config.SMTPConfig) (mailer.Mailer, error) { return namedMailer{host: c.Host}, nil },
	})
	return f
}

func write(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestNoConfigFileBehavesAsBefore(t *testing.T) {
	f := newFixture(t, "")
	f.svc = NewStackConfigService(Deps{Env: envCfg(""), Settings: f.settings, Email: f.email, Audit: f.audit})
	if err := f.svc.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.settings.sets != 0 || f.email.name != "" {
		t.Fatal("nothing must be touched without BOSON_CONFIG")
	}
	st := f.svc.Status()
	if st.Enabled || !st.OK {
		t.Fatalf("%+v", st)
	}
	if strings.Join(f.svc.CORSOrigins(), ",") != "https://app.example.com" {
		t.Fatal(f.svc.CORSOrigins())
	}
}

func TestMissingFileIsDatabaseMode(t *testing.T) {
	f := newFixture(t, "")
	if err := f.svc.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.settings.file != nil || f.settings.sets != 1 {
		t.Fatal("missing file → database mode")
	}
	if f.email.name != "env-site" || f.mail.Current().(namedMailer).host != "boot" {
		t.Fatal(f.email.name, f.mail.Current())
	}
	if st := f.svc.Status(); !st.Enabled || st.Present || !st.OK {
		t.Fatalf("%+v", st)
	}
}

func TestLoadAppliesFileAndReloadIsLive(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, `version: 1
network: { name: File Net }
auth:
  registration: closed
  cors_allowed_origins: [https://admin.example.com]
`)
	if err := f.svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if f.settings.file == nil || f.settings.file.Registration != "closed" || !f.settings.file.GuestAccess {
		t.Fatalf("%+v", f.settings.file)
	}
	if f.email.name != "File Net" {
		t.Fatal(f.email.name)
	}
	if strings.Join(f.svc.CORSOrigins(), ",") != "https://admin.example.com" {
		t.Fatal(f.svc.CORSOrigins())
	}
	// CORS origins are also web origins for SSO return_to (cookie mode).
	if _, mode, err := f.returnTo.Resolve("https://admin.example.com/after", ""); err != nil || mode != sso.ModeCookie {
		t.Fatal(mode, err)
	}
	if len(f.audit.events) != 0 {
		t.Fatal("start-up load is not a reload", f.audit.events)
	}
	// SMTP in the file is applied at start (env host was env-smtp).
	if f.mail.Current().(namedMailer).host != "env-smtp" {
		t.Fatal(f.mail.Current())
	}

	write(t, f.path, `version: 1
network: { name: File Net }
auth:
  registration: invite
  smtp: { host: new-smtp }
`)
	f.svc.Check(ctx)
	if f.settings.file.Registration != "invite" {
		t.Fatal(f.settings.file)
	}
	// cors_allowed_origins removed → back to the env value.
	if strings.Join(f.svc.CORSOrigins(), ",") != "https://app.example.com" {
		t.Fatal(f.svc.CORSOrigins())
	}
	if _, _, err := f.returnTo.Resolve("https://admin.example.com/after", sso.ModeCookie); err == nil {
		t.Fatal("removed origin must no longer be a web origin")
	}
	if f.mail.Current().(namedMailer).host != "new-smtp" {
		t.Fatal("SMTP must be rebuilt live", f.mail.Current())
	}
	if len(f.audit.events) != 1 || f.audit.events[0] != "config_reloaded" {
		t.Fatal(f.audit.events)
	}
	meta := f.audit.metas[0]
	if meta["actor"] != Actor {
		t.Fatal(meta)
	}
	if got := strings.Join(meta["changed"].([]string), ","); got != "auth.cors_allowed_origins,auth.registration,auth.smtp.host" {
		t.Fatal(got)
	}
	if st := f.svc.Status(); !st.OK || len(st.RestartRequired) != 0 {
		t.Fatalf("everything in auth applies live: %+v", st)
	}
}

func TestInvalidFileKeepsLastGood(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, "auth:\n  registration: closed\n")
	if err := f.svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	write(t, f.path, "auth:\n  registration: wide-open\n")
	f.svc.Check(ctx)
	if f.settings.file.Registration != "closed" {
		t.Fatal("last good config must stay")
	}
	st := f.svc.Status()
	if st.OK || st.ErrorLine != 2 || st.ErrorColumn != 17 || !strings.Contains(st.Error, "open, invite or closed") {
		t.Fatalf("%+v", st)
	}
	if len(f.audit.events) != 0 {
		t.Fatal(f.audit.events)
	}
}

func TestInvalidFileAtStartRunsOnEnv(t *testing.T) {
	f := newFixture(t, "auth:\n  registration: [\n")
	if err := f.svc.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.settings.file != nil || f.email.name != "env-site" {
		t.Fatal("invalid at start-up → env/database values", f.settings.file)
	}
	if st := f.svc.Status(); st.OK || st.LoadedAt != nil || st.Error == "" {
		t.Fatalf("%+v", st)
	}
}

func TestCommentOnlyChangeIsNotAudited(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, "auth:\n  registration: closed\n")
	_ = f.svc.Load(ctx)
	write(t, f.path, "# hello\nauth:\n  registration: closed\nvoice: { max_rooms_per_user: 3 }\n")
	f.svc.Check(ctx)
	if len(f.audit.events) != 0 {
		t.Fatal(f.audit.events)
	}
}

func TestFileRemovedSwitchesToDatabase(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, "network: { name: File }\nauth:\n  registration: closed\n")
	_ = f.svc.Load(ctx)
	_ = os.Remove(f.path)
	f.svc.Check(ctx)
	if f.settings.file != nil || f.email.name != "env-site" {
		t.Fatal(f.settings.file, f.email.name)
	}
	if len(f.audit.events) != 1 || f.audit.metas[0]["mode"] != "db" {
		t.Fatal(f.audit.metas)
	}
}

type brandSpy struct {
	mu   sync.Mutex
	cur  *branding.Snapshot
	sets int
}

func (b *brandSpy) Set(s *branding.Snapshot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cur, b.sets = s, b.sets+1
}

const svgLogo = `<svg xmlns="http://www.w3.org/2000/svg"/>`

func TestBrandingAndEmailReloadLive(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, "")
	brandDir := filepath.Join(filepath.Dir(f.path), "branding")
	if err := os.Mkdir(brandDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(brandDir, "logo-1.svg"), []byte(svgLogo), 0o644); err != nil {
		t.Fatal(err)
	}
	env := envCfg(f.path)
	env.AppConfig.BrandingDir = brandDir
	spy := &brandSpy{}
	svc := branding.NewBrandingService(env.HTTPConfig.PublicURL)
	f.svc = NewStackConfigService(Deps{
		Env: env, Settings: f.settings, Email: f.email, Branding: multiBrander{spy, svc}, Audit: f.audit,
	})
	write(t, f.path, `version: 1
branding:
  theme: { colors: { accent: "#7c3aed" } }
  images: { logo: logo-1.svg }
auth:
  email: { sender_name: Example Chat, accent: "#7c3aed" }
`)
	if err := f.svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	doc, ok := svc.Document(ctx)
	if !ok || !strings.Contains(string(doc.JSON), `"logo":"https://auth.example.com/v1/branding/assets/logo-1.svg?v=`) {
		t.Fatal("branding not applied", ok)
	}
	if f.email.cfg == nil || f.email.cfg.SenderName != "Example Chat" {
		t.Fatalf("%+v", f.email.cfg)
	}

	// The admin panel writes a new image, then the file pointing at it.
	if err := os.WriteFile(filepath.Join(brandDir, "logo-2.svg"), []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="2"/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	write(t, f.path, `version: 1
branding:
  theme: { colors: { accent: "#7c3aed" } }
  images: { logo: logo-2.svg }
auth:
  email: { sender_name: Renamed }
`)
	f.svc.Check(ctx)
	doc2, _ := svc.Document(ctx)
	if doc2.ETag == doc.ETag || !strings.Contains(string(doc2.JSON), "logo-2.svg") {
		t.Fatal("new logo must be live")
	}
	if f.email.cfg.SenderName != "Renamed" {
		t.Fatal(f.email.cfg)
	}
	if got := strings.Join(f.audit.metas[len(f.audit.metas)-1]["changed"].([]string), ","); got != "auth.email.accent,auth.email.sender_name,branding.images.logo" {
		t.Fatal(got)
	}

	// A missing image keeps the last good config and is reported.
	write(t, f.path, "version: 1\nbranding:\n  images:\n    logo: gone.svg\n")
	f.svc.Check(ctx)
	if d, _ := svc.Document(ctx); d.ETag != doc2.ETag {
		t.Fatal("last good branding must stay")
	}
	st := f.svc.Status()
	if st.OK || st.ErrorLine != 4 || st.ErrorColumn != 11 || !strings.Contains(st.Error, "gone.svg not found") {
		t.Fatalf("%+v", st)
	}

	// Removing the sections: no branding, built-in emails.
	write(t, f.path, "version: 1\nauth: { registration: open }\n")
	f.svc.Check(ctx)
	if _, ok := svc.Document(ctx); ok || f.email.cfg != nil || spy.cur != nil {
		t.Fatal("sections removed → nothing configured")
	}
	// The whole file removed: same.
	_ = os.Remove(f.path)
	f.svc.Check(ctx)
	if spy.cur != nil || f.email.cfg != nil {
		t.Fatal("file removed → nothing configured")
	}
}

type multiBrander []Brander

func (m multiBrander) Set(s *branding.Snapshot) {
	for _, b := range m {
		b.Set(s)
	}
}

// The email MJML / HTML files: read from the emails directory next to the
// config file, live on reload, and a bad file keeps the last good config.
func TestEmailFilesReloadLive(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, "")
	dir := filepath.Join(filepath.Dir(f.path), "emails")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	put := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("layout-1.mjml", "<mjml/>")
	put("layout-1.html", "<div>ONE {{content}}</div>")
	write(t, f.path, `version: 1
auth:
  email:
    layout:
      mjml: emails/layout-1.mjml
      html: emails/layout-1.html
`)
	if err := f.svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if c := f.email.cfg; c == nil || c.Layout == nil || c.Layout.Source != "<div>ONE {{content}}</div>" {
		t.Fatalf("%+v", f.email.cfg)
	}

	// The admin panel writes new files, then the config pointing at them.
	put("layout-2.html", "<div>TWO {{content}}</div>")
	put("invite-1.html", `<a href="{{link}}">join</a>`)
	write(t, f.path, `version: 1
auth:
  email:
    layout: { html: layout-2.html }
    templates:
      invite: { html: invite-1.html }
`)
	f.svc.Check(ctx)
	if c := f.email.cfg; c.Layout.Source != "<div>TWO {{content}}</div>" || c.Templates[config.EmailInvite].Files.Source != `<a href="{{link}}">join</a>` {
		t.Fatalf("%+v", c)
	}
	if got := strings.Join(f.audit.metas[len(f.audit.metas)-1]["changed"].([]string), ","); got != "auth.email.layout.html,auth.email.layout.mjml,auth.email.templates.invite.html" {
		t.Fatal(got)
	}
	good := f.email.cfg

	// Invalid: a layout without {{content}}, a missing file. The last good
	// config stays and the status points at the file name.
	put("layout-3.html", "<div>no placeholder</div>")
	for _, c := range []struct {
		file      string
		line, col int
		msg       string
	}{
		{"version: 1\nauth:\n  email:\n    layout: { html: layout-3.html }\n", 4, 21, "auth.email.layout.html: layout-3.html must contain {{content}}"},
		{"version: 1\nauth:\n  email:\n    templates:\n      invite:\n        html: gone.html\n", 6, 15, "gone.html not found in " + dir},
		{"version: 1\nauth:\n  email:\n    layout: { html: ../boson.html }\n", 4, 21, "plain file name"},
	} {
		write(t, f.path, c.file)
		f.svc.Check(ctx)
		st := f.svc.Status()
		if f.email.cfg != good || st.OK || st.ErrorLine != c.line || st.ErrorColumn != c.col || !strings.Contains(st.Error, c.msg) {
			t.Fatalf("%+v", st)
		}
	}
	// Fixed: applies.
	put("layout-3.html", "<div>THREE {{content}}</div>")
	write(t, f.path, "version: 1\nauth:\n  email:\n    layout: { html: layout-3.html }\n")
	f.svc.Check(ctx)
	if st := f.svc.Status(); !st.OK || f.email.cfg.Layout.Source != "<div>THREE {{content}}</div>" {
		t.Fatalf("%+v", st)
	}
}

func TestNetworkChannelsReloadLive(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, "version: 1\nirc:\n  channels: [{ name: \"#Lobby\", topic: Hi, autojoin: true }]\n  channel_founder: thelion\n")
	if err := f.svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	irc := f.svc.Effective().IRCConfig
	if len(irc.Channels) != 1 || !reflect.DeepEqual(irc.Channels[0], config.NetworkChannel{Name: "#Lobby", Topic: "Hi", Autojoin: true}) || irc.ChannelFounder != "thelion" {
		t.Fatalf("%+v", irc)
	}
	write(t, f.path, "version: 1\nirc:\n  channels: [{ name: \"#Lobby\", autojoin: true }, { name: \"#help\", roles: [Admin] }]\n  autojoin_guests: false\n")
	f.svc.Check(ctx)
	if irc = f.svc.Effective().IRCConfig; len(irc.Channels) != 2 || irc.Channels[0].Topic != "" || !irc.Channels[1].Restricted() || irc.ChannelFounder != "" || irc.AutojoinGuests {
		t.Fatalf("reloaded %+v", irc)
	}
	if got := strings.Join(f.audit.metas[0]["changed"].([]string), ","); got != "irc.autojoin_guests,irc.channel_founder,irc.channels" {
		t.Fatal(got)
	}
	// an invalid list keeps the last good one
	write(t, f.path, "version: 1\nirc:\n  channels: [{ name: lobby }]\n")
	f.svc.Check(ctx)
	if st := f.svc.Status(); st.OK || !strings.Contains(st.Error, "irc.channels[0].name") || len(f.svc.Effective().IRCConfig.Channels) != 2 {
		t.Fatalf("%+v", st)
	}
}
