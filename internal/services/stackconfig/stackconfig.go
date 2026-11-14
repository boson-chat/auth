// Package stackconfig applies the stack config file (BOSON_CONFIG) to the
// running service: network settings, CORS origins, SMTP, the site name,
// branding (theme and images) and the email templates are reloaded live when the file changes. Without BOSON_CONFIG (or while
// the file is missing) the env values and the database apply, as before.
package stackconfig

import (
	"context"
	"strings"
	"sync/atomic"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/configfile"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/mailer"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/services/branding"
	"github.com/boson-chat/auth/internal/services/settings"
	"github.com/boson-chat/auth/internal/services/sso"
)

// Actor is the audit actor of config_reloaded.
const Actor = "config file"

// Emailer is the email service's live configuration.
type Emailer interface {
	SetSiteName(name string)
	SetConfig(c *config.EmailConfig)
}

// Brander is the branding service's live snapshot.
type Brander interface{ Set(s *branding.Snapshot) }

// loaded is a valid file: auth's sections plus the branding images read
// from the branding directory.
type loaded struct {
	file     config.FileConfig
	branding *branding.Snapshot
}

// Deps are the parts the file reconfigures.
type Deps struct {
	// Env is the configuration from env vars only (no file applied).
	Env      config.Config
	Settings settings.SettingsServiceImpl
	Email    Emailer
	// Branding receives the branding: section (nil: not wired).
	Branding Brander
	// Mailer is replaced when the smtp keys change. Nil: leave the mailer
	// alone (a test mailer was injected).
	Mailer   *mailer.Swappable
	ReturnTo *sso.ReturnToPolicy
	Audit    audit.AuditServiceImpl
	// NewMailer builds the SMTP mailer (default mailer.New).
	NewMailer func(config.SMTPConfig) (mailer.Mailer, error)
	Now       func() time.Time
}

type StackConfigServiceImpl interface {
	// Load reads the file at start-up. An invalid file is an error.
	Load(ctx context.Context) error
	// Run watches the file until ctx is done (no-op without BOSON_CONFIG).
	Run(ctx context.Context)
	// Check re-reads the file now (tests, SIGHUP-style triggers).
	Check(ctx context.Context)
	// Status is GET /internal/config/status.
	Status() configfile.Status
	// CORSOrigins are the allowed credentialed origins now (read-only slice).
	CORSOrigins() []string
	// Effective is the env config with the file applied.
	Effective() config.Config
}

type StackConfigService struct {
	d    Deps
	w    *configfile.Watcher[loaded]
	cors atomic.Pointer[[]string]
	eff  atomic.Pointer[config.Config]
}

func NewStackConfigService(d Deps) *StackConfigService {
	if d.NewMailer == nil {
		d.NewMailer = mailer.New
	}
	s := &StackConfigService{d: d}
	s.setEffective(d.Env)
	if path := d.Env.AppConfig.ConfigFile; path != "" {
		log := logger.FromCtx(context.Background()).With().Str("component", "config").Logger()
		s.w = configfile.New(configfile.Options[loaded]{
			Path:  path,
			Load:  s.load,
			Apply: s.apply,
			Poll:  d.Env.AppConfig.ConfigPoll,
			Log:   &log,
			Now:   d.Now,
		})
	}
	return s
}

func (s *StackConfigService) load(doc *configfile.Document) (loaded, error) {
	f, err := config.LoadFileConfig(doc)
	if err != nil {
		return loaded{}, err
	}
	// Whole-config checks (they name env vars; the file's own values
	// were checked with positions above).
	if err := s.d.Env.WithFile(f).Validate(); err != nil {
		return loaded{}, err
	}
	// The images must exist and be valid, or the last good config stays.
	snap, err := branding.Prepare(f.Branding, s.d.Env.AppConfig.BrandingDirectory(), s.d.Env.HTTPConfig.PublicURL)
	if err != nil {
		return loaded{}, err
	}
	return loaded{file: f, branding: snap}, nil
}

func (s *StackConfigService) setEffective(c config.Config) {
	s.eff.Store(&c)
	cors := config.SplitList(c.HTTPConfig.CORSAllowedOrigins)
	for i, o := range cors {
		cors[i] = strings.TrimRight(o, "/")
	}
	s.cors.Store(&cors)
}

func (s *StackConfigService) apply(ctx context.Context, lc configfile.Change[loaded]) {
	c := configfile.Change[config.FileConfig]{Initial: lc.Initial,
		Prev: configfile.State[config.FileConfig]{Present: lc.Prev.Present, Value: lc.Prev.Value.file},
		Next: configfile.State[config.FileConfig]{Present: lc.Next.Present, Value: lc.Next.Value.file}}
	log := logger.FromCtx(ctx)
	prev := *s.eff.Load()
	eff := s.d.Env
	if c.Next.Present {
		eff = s.d.Env.WithFile(c.Next.Value)
		if len(c.Next.Value.Unknown) > 0 {
			log.Warn().Strs("keys", c.Next.Value.Unknown).Msg("config file: ignoring unknown keys")
		}
	}
	// Absent file / section: no branding and Boson's built-in emails.
	if s.d.Branding != nil {
		s.d.Branding.Set(lc.Next.Value.branding)
	}
	if c.Next.Present {
		s.d.Settings.SetFile(&eff.AccountConfig)
	} else {
		s.d.Settings.SetFile(nil)
	}
	if s.d.Email != nil {
		s.d.Email.SetSiteName(eff.AppConfig.SiteName)
		s.d.Email.SetConfig(c.Next.Value.Email)
	}
	s.setEffective(eff)
	if s.d.ReturnTo != nil {
		h := eff.HTTPConfig
		s.d.ReturnTo.SetWebOrigins(append([]string{h.AppURL, h.PublicURL}, config.SplitList(h.CORSAllowedOrigins)...))
	}
	if s.d.Mailer != nil && (c.Initial && c.Next.Present || eff.SMTPConfig != prev.SMTPConfig) {
		if m, err := s.d.NewMailer(eff.SMTPConfig); err != nil {
			log.Error().Err(err).Msg("config file: SMTP settings rejected; keeping the previous mailer")
		} else {
			s.d.Mailer.Set(m)
		}
	}
	if c.Initial {
		return
	}
	var before, after map[string]any
	if c.Prev.Present {
		before = c.Prev.Value.Flatten()
	}
	if c.Next.Present {
		after = c.Next.Value.Flatten()
	}
	changed := configfile.ChangedKeys(before, after)
	meta := map[string]any{"actor": Actor, "changed": changed, "present": c.Next.Present}
	if !c.Next.Present || !c.Prev.Present {
		// Switching between file and database mode is itself a change.
		meta["mode"] = map[bool]string{true: settings.SourceFile, false: settings.SourceDB}[c.Next.Present]
	} else if len(changed) == 0 {
		return // only comments / other services' sections changed
	}
	log.Info().Strs("changed", changed).Msg("config reloaded")
	s.d.Audit.Record(ctx, "", audit.EventConfigReloaded, meta)
}

func (s *StackConfigService) Load(ctx context.Context) error {
	if s.w == nil {
		return nil
	}
	return s.w.Load(ctx)
}

func (s *StackConfigService) Run(ctx context.Context) {
	if s.w != nil {
		s.w.Run(ctx)
	}
}

func (s *StackConfigService) Check(ctx context.Context) {
	if s.w != nil {
		s.w.Check(ctx)
	}
}

func (s *StackConfigService) Status() configfile.Status {
	if s.w == nil {
		return configfile.Status{OK: true, RestartRequired: []string{}}
	}
	return s.w.Status()
}

func (s *StackConfigService) CORSOrigins() []string { return *s.cors.Load() }

func (s *StackConfigService) Effective() config.Config { return *s.eff.Load() }
