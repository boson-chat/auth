package stackconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	auditrepo "github.com/boson-chat/auth/internal/db/repositories/audit"
	"github.com/boson-chat/auth/internal/mailer"
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

type fakeEmail struct{ name string }

func (f *fakeEmail) SetSiteName(n string) { f.name = n }

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

func TestInvalidFileAtStartFails(t *testing.T) {
	f := newFixture(t, "auth:\n  registration: [\n")
	if err := f.svc.Load(context.Background()); err == nil {
		t.Fatal("an invalid file at start-up must fail")
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
