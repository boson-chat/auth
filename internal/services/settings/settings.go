// Package settings serves the runtime network settings: registration mode,
// email verification, who may create IRC text and voice channels, and the
// IRC channel lifecycle (auto-registration, expiry of idle channels) and
// whether IRC lets guests (no account) connect and whether guests may join
// voice.
// Values stored in network_settings override the env defaults; reads are
// cached for SETTINGS_CACHE_TTL so other replicas pick up changes quickly.
//
// With the stack config file (BOSON_CONFIG) present the file is the source
// of truth instead (SetFile): the effective values are file > env >
// default, network_settings is ignored and Update answers 409
// managed_by_config_file.
package settings

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	settingsrepo "github.com/boson-chat/auth/internal/db/repositories/settings"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/services/audit"
)

// Settings are the effective values.
type Settings struct {
	Registration             string     `json:"registration"`
	RequireEmailVerification bool       `json:"require_email_verification"`
	ChannelCreation          string     `json:"channel_creation"`
	VoiceChannelCreation     string     `json:"voice_channel_creation"`
	ChannelAutoRegister      bool       `json:"channel_auto_register"`
	ChannelExpiryDays        int        `json:"channel_expiry_days"`
	GuestAccess              bool       `json:"guest_access"`
	GuestVoice               bool       `json:"guest_voice"`
	UpdatedAt                *time.Time `json:"updated_at"`
	UpdatedBy                *string    `json:"updated_by"`
	// Source is where the values come from: "file" (stack config file,
	// read-only here) or "db" (network_settings over env defaults).
	Source string `json:"source"`

	// EmailConfigured: auth can send email (a mail server is configured,
	// or ENV=development logs emails). Not a setting: filled in by Get.
	EmailConfigured bool `json:"email_configured"`
	// RequireEmailVerificationEffective is what sign-in enforces:
	// RequireEmailVerification, except that it is off while auth can't
	// send the verification email (local backend without a mail server).
	// With the NickServ backend the services verify, so it is
	// RequireEmailVerification.
	RequireEmailVerificationEffective bool `json:"require_email_verification_effective"`
}

// Sources.
const (
	SourceFile = "file"
	SourceDB   = "db"
)

// ErrManagedByConfigFile: the settings are read-only because the stack
// config file manages them.
var ErrManagedByConfigFile = apperr.New(http.StatusConflict, "managed_by_config_file",
	"these settings are managed by the stack config file (BOSON_CONFIG); edit the file or the admin panel instead")

// Patch is a partial update; nil fields are left alone.
type Patch struct {
	Registration             *string `json:"registration"`
	RequireEmailVerification *bool   `json:"require_email_verification"`
	ChannelCreation          *string `json:"channel_creation"`
	VoiceChannelCreation     *string `json:"voice_channel_creation"`
	ChannelAutoRegister      *bool   `json:"channel_auto_register"`
	ChannelExpiryDays        *int    `json:"channel_expiry_days"`
	GuestAccess              *bool   `json:"guest_access"`
	GuestVoice               *bool   `json:"guest_voice"`
}

func (p Patch) empty() bool {
	return p.Registration == nil && p.RequireEmailVerification == nil && p.ChannelCreation == nil && p.VoiceChannelCreation == nil &&
		p.ChannelAutoRegister == nil && p.ChannelExpiryDays == nil && p.GuestAccess == nil && p.GuestVoice == nil
}

// Validate checks every set field.
func (p Patch) Validate() error {
	if p.Registration != nil && !config.ValidRegistration(*p.Registration) {
		return apperr.Invalid("registration must be open, invite or closed")
	}
	if p.ChannelCreation != nil && !config.ValidChannelCreation(*p.ChannelCreation) {
		return apperr.Invalid("channel_creation must be registered or admins")
	}
	if p.VoiceChannelCreation != nil && !config.ValidVoiceChannelCreation(*p.VoiceChannelCreation) {
		return apperr.Invalid("voice_channel_creation must be admins, founders or registered")
	}
	if p.ChannelExpiryDays != nil && !config.ValidChannelExpiryDays(*p.ChannelExpiryDays) {
		return apperr.Invalid(fmt.Sprintf("channel_expiry_days must be between 0 and %d (0 = never expire)", config.MaxChannelExpiryDays))
	}
	return nil
}

type SettingsServiceImpl interface {
	// Get returns the effective settings (cached briefly).
	Get(ctx context.Context) (Settings, error)
	// Update applies a partial change, audit-logs it (settings_updated with
	// old/new values) and returns the new settings. ErrManagedByConfigFile
	// in file mode.
	Update(ctx context.Context, actorID string, p Patch) (Settings, error)
	// SetFile switches to file mode with the effective values (file over
	// env defaults); nil switches back to the database.
	SetFile(v *config.AccountConfig)
}

type SettingsService struct {
	Repository settingsrepo.SettingsRepositoryImpl
	Tx         db.TxManagerImpl
	Audit      audit.AuditServiceImpl
	Defaults   config.AccountConfig
	TTL        time.Duration
	Now        func() time.Time

	// EmailConfigured reports whether email can be sent now (nil: it can).
	// Without it, email verification is off whatever the setting says.
	EmailConfigured func() bool
	// ServicesVerifyEmail: the NickServ backend, whose services send and
	// check the verification emails; auth's mailer doesn't matter then.
	ServicesVerifyEmail bool

	file atomic.Pointer[config.AccountConfig]
	// overridden: the "verification is off, no mail server" warning was
	// logged (reset once email works again, so a later loss logs again).
	overridden atomic.Bool

	mu       sync.Mutex
	cached   Settings
	cachedAt time.Time
	valid    bool
}

func NewSettingsService(repo settingsrepo.SettingsRepositoryImpl, tx db.TxManagerImpl, auditSvc audit.AuditServiceImpl,
	defaults config.AccountConfig, now func() time.Time) SettingsServiceImpl {
	if now == nil {
		now = time.Now
	}
	return &SettingsService{Repository: repo, Tx: tx, Audit: auditSvc, Defaults: defaults, TTL: defaults.SettingsCacheTTL, Now: now}
}

func (s *SettingsService) effective(r *settingsrepo.Row) Settings {
	out := Settings{
		Registration:             s.Defaults.Registration,
		RequireEmailVerification: s.Defaults.RequireEmailVerification,
		ChannelCreation:          s.Defaults.ChannelCreation,
		VoiceChannelCreation:     s.Defaults.VoiceChannelCreation,
		ChannelAutoRegister:      s.Defaults.ChannelAutoRegister,
		ChannelExpiryDays:        s.Defaults.ChannelExpiryDays,
		GuestAccess:              s.Defaults.GuestAccess,
		GuestVoice:               s.Defaults.GuestVoice,
		UpdatedAt:                r.UpdatedAt,
		UpdatedBy:                r.UpdatedBy,
		Source:                   SourceDB,
	}
	if r.Registration != nil {
		out.Registration = *r.Registration
	}
	if r.RequireEmailVerification != nil {
		out.RequireEmailVerification = *r.RequireEmailVerification
	}
	if r.ChannelCreation != nil {
		out.ChannelCreation = *r.ChannelCreation
	}
	if r.VoiceChannelCreation != nil {
		out.VoiceChannelCreation = *r.VoiceChannelCreation
	}
	if r.ChannelAutoRegister != nil {
		out.ChannelAutoRegister = *r.ChannelAutoRegister
	}
	if r.ChannelExpiryDays != nil {
		out.ChannelExpiryDays = *r.ChannelExpiryDays
	}
	if r.GuestAccess != nil {
		out.GuestAccess = *r.GuestAccess
	}
	if r.GuestVoice != nil {
		out.GuestVoice = *r.GuestVoice
	}
	return out
}

// fromFile renders file-mode values.
func fromFile(a *config.AccountConfig) Settings {
	return Settings{
		Registration: a.Registration, RequireEmailVerification: a.RequireEmailVerification,
		ChannelCreation: a.ChannelCreation, VoiceChannelCreation: a.VoiceChannelCreation,
		ChannelAutoRegister: a.ChannelAutoRegister, ChannelExpiryDays: a.ChannelExpiryDays,
		GuestAccess: a.GuestAccess, GuestVoice: a.GuestVoice, Source: SourceFile,
	}
}

func (s *SettingsService) SetFile(v *config.AccountConfig) {
	if v != nil {
		c := *v
		v = &c
	}
	s.file.Store(v)
	s.mu.Lock()
	s.valid = false // DB mode again: re-read the row
	s.mu.Unlock()
}

func (s *SettingsService) Get(ctx context.Context) (Settings, error) {
	if f := s.file.Load(); f != nil {
		return s.withEmail(ctx, fromFile(f)), nil
	}
	s.mu.Lock()
	if s.valid && s.Now().Sub(s.cachedAt) < s.TTL {
		v := s.cached
		s.mu.Unlock()
		return s.withEmail(ctx, v), nil
	}
	s.mu.Unlock()
	row, err := s.Repository.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	v := s.effective(row)
	s.store(v)
	return s.withEmail(ctx, v), nil
}

// withEmail fills in the email state (live: the mailer can change with the
// stack config file) and the effective email verification, logging once
// when the setting is overridden.
func (s *SettingsService) withEmail(ctx context.Context, v Settings) Settings {
	v.EmailConfigured = s.EmailConfigured == nil || s.EmailConfigured()
	v.RequireEmailVerificationEffective = v.RequireEmailVerification && (v.EmailConfigured || s.ServicesVerifyEmail)
	if v.RequireEmailVerification && !v.RequireEmailVerificationEffective {
		if s.overridden.CompareAndSwap(false, true) {
			logger.FromCtx(ctx).Warn().Msg("email verification is OFF: require_email_verification is on, but no mail server " +
				"is configured (SMTP_HOST / auth.smtp.host is empty), so new accounts can sign in without verifying their email")
		}
	} else if v.EmailConfigured {
		s.overridden.Store(false)
	}
	return v
}

func (s *SettingsService) store(v Settings) {
	s.mu.Lock()
	s.cached, s.cachedAt, s.valid = v, s.Now(), true
	s.mu.Unlock()
}

func (s *SettingsService) Update(ctx context.Context, actorID string, p Patch) (Settings, error) {
	if s.file.Load() != nil {
		return Settings{}, ErrManagedByConfigFile
	}
	if p.empty() {
		return Settings{}, apperr.Invalid("nothing to update")
	}
	if err := p.Validate(); err != nil {
		return Settings{}, err
	}
	var before, after Settings
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		row, err := s.Repository.GetForUpdate(ctx)
		if err != nil {
			return err
		}
		before = s.effective(row)
		if p.Registration != nil {
			row.Registration = p.Registration
		}
		if p.RequireEmailVerification != nil {
			row.RequireEmailVerification = p.RequireEmailVerification
		}
		if p.ChannelCreation != nil {
			row.ChannelCreation = p.ChannelCreation
		}
		if p.VoiceChannelCreation != nil {
			row.VoiceChannelCreation = p.VoiceChannelCreation
		}
		if p.ChannelAutoRegister != nil {
			row.ChannelAutoRegister = p.ChannelAutoRegister
		}
		if p.ChannelExpiryDays != nil {
			row.ChannelExpiryDays = p.ChannelExpiryDays
		}
		if p.GuestAccess != nil {
			row.GuestAccess = p.GuestAccess
		}
		if p.GuestVoice != nil {
			row.GuestVoice = p.GuestVoice
		}
		now := s.Now().UTC()
		row.UpdatedAt = &now
		row.UpdatedBy = nil
		if actorID != "" {
			row.UpdatedBy = &actorID
		}
		if err := s.Repository.Save(ctx, row); err != nil {
			return err
		}
		after = s.effective(row)
		return nil
	})
	if err != nil {
		return Settings{}, err
	}
	s.store(after)
	oldV, newV := diff(before, after)
	s.Audit.Record(ctx, actorID, audit.EventSettingsUpdated, map[string]any{"old": oldV, "new": newV})
	return s.withEmail(ctx, after), nil
}

// diff returns the changed fields' old and new values.
func diff(a, b Settings) (map[string]any, map[string]any) {
	oldV, newV := map[string]any{}, map[string]any{}
	add := func(name string, x, y any) {
		if x != y {
			oldV[name], newV[name] = x, y
		}
	}
	add("registration", a.Registration, b.Registration)
	add("require_email_verification", a.RequireEmailVerification, b.RequireEmailVerification)
	add("channel_creation", a.ChannelCreation, b.ChannelCreation)
	add("voice_channel_creation", a.VoiceChannelCreation, b.VoiceChannelCreation)
	add("channel_auto_register", a.ChannelAutoRegister, b.ChannelAutoRegister)
	add("channel_expiry_days", a.ChannelExpiryDays, b.ChannelExpiryDays)
	add("guest_access", a.GuestAccess, b.GuestAccess)
	add("guest_voice", a.GuestVoice, b.GuestVoice)
	return oldV, newV
}
