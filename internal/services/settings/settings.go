// Package settings serves the runtime network settings: registration mode,
// email verification, who may create IRC text and voice channels, and the
// IRC channel lifecycle (auto-registration, expiry of idle channels) and
// whether IRC lets guests (no account) connect.
// Values stored in network_settings override the env defaults; reads are
// cached for SETTINGS_CACHE_TTL so other replicas pick up changes quickly.
package settings

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	settingsrepo "github.com/boson-chat/auth/internal/db/repositories/settings"
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
	UpdatedAt                *time.Time `json:"updated_at"`
	UpdatedBy                *string    `json:"updated_by"`
}

// Patch is a partial update; nil fields are left alone.
type Patch struct {
	Registration             *string `json:"registration"`
	RequireEmailVerification *bool   `json:"require_email_verification"`
	ChannelCreation          *string `json:"channel_creation"`
	VoiceChannelCreation     *string `json:"voice_channel_creation"`
	ChannelAutoRegister      *bool   `json:"channel_auto_register"`
	ChannelExpiryDays        *int    `json:"channel_expiry_days"`
	GuestAccess              *bool   `json:"guest_access"`
}

func (p Patch) empty() bool {
	return p.Registration == nil && p.RequireEmailVerification == nil && p.ChannelCreation == nil && p.VoiceChannelCreation == nil &&
		p.ChannelAutoRegister == nil && p.ChannelExpiryDays == nil && p.GuestAccess == nil
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
	// old/new values) and returns the new settings.
	Update(ctx context.Context, actorID string, p Patch) (Settings, error)
}

type SettingsService struct {
	Repository settingsrepo.SettingsRepositoryImpl
	Tx         db.TxManagerImpl
	Audit      audit.AuditServiceImpl
	Defaults   config.AccountConfig
	TTL        time.Duration
	Now        func() time.Time

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
		UpdatedAt:                r.UpdatedAt,
		UpdatedBy:                r.UpdatedBy,
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
	return out
}

func (s *SettingsService) Get(ctx context.Context) (Settings, error) {
	s.mu.Lock()
	if s.valid && s.Now().Sub(s.cachedAt) < s.TTL {
		v := s.cached
		s.mu.Unlock()
		return v, nil
	}
	s.mu.Unlock()
	row, err := s.Repository.Get(ctx)
	if err != nil {
		return Settings{}, err
	}
	v := s.effective(row)
	s.store(v)
	return v, nil
}

func (s *SettingsService) store(v Settings) {
	s.mu.Lock()
	s.cached, s.cachedAt, s.valid = v, s.Now(), true
	s.mu.Unlock()
}

func (s *SettingsService) Update(ctx context.Context, actorID string, p Patch) (Settings, error) {
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
	return after, nil
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
	return oldV, newV
}
