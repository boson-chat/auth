// Package audit records security-relevant events. Recording never fails the
// caller's operation; errors are logged.
package audit

import (
	"context"
	"time"

	"github.com/boson-chat/auth/internal/db/repositories"
	auditrepo "github.com/boson-chat/auth/internal/db/repositories/audit"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/reqmeta"
)

// Event names.
const (
	EventRegister             = "register"
	EventEmailVerified        = "email_verified"
	EventLogin                = "login"
	EventLoginFailed          = "login_failed"
	EventLogout               = "logout"
	EventRefreshReuse         = "refresh_token_reuse"
	EventPasswordResetRequest = "password_reset_requested"
	EventPasswordReset        = "password_reset"
	EventPasswordChanged      = "password_changed"
	EventSessionRevoked       = "session_revoked"
	EventInternalVerify       = "internal_verify_password"
	EventAdminUserCreated     = "admin_user_created"
	EventAdminUserDisabled    = "admin_user_disabled"
	EventAdminUserEnabled     = "admin_user_enabled"
	EventAdminRoleChanged     = "admin_role_changed"
	EventAdminSessionRevoked  = "admin_session_revoked"
	EventAdminInviteCreated   = "admin_invite_created"
	EventAdminInviteRevoked   = "admin_invite_revoked"
	EventKeyCreated           = "signing_key_created"
	EventSettingsUpdated      = "settings_updated"
	// EventConfigReloaded: the stack config file changed (meta: actor
	// "config file", changed keys).
	EventConfigReloaded     = "config_reloaded"
	EventAdminResetSent     = "admin_password_reset_sent"
	EventAdminVerifySent    = "admin_verification_sent"
	EventSSOLinked          = "sso_identity_linked"
	EventSSOUnlinked        = "sso_identity_unlinked"
	EventSSOFailed          = "sso_login_failed"
	EventSSOProviderCreated = "sso_provider_created"
	EventSSOProviderUpdated = "sso_provider_updated"
	EventSSOProviderDeleted = "sso_provider_deleted"
	EventRoleCreated        = "role_created"
	EventRoleUpdated        = "role_updated"
	EventRoleDeleted        = "role_deleted"
	EventUserRolesChanged   = "user_roles_changed"
	// EventEmailTestSent: POST /internal/email/test (meta: template, to,
	// outcome, logged_only).
	EventEmailTestSent = "email_test_sent"
)

type AuditServiceImpl interface {
	// Record stores an event. userID may be "" (unknown user).
	Record(ctx context.Context, userID, event string, meta map[string]any)
	// RecordTarget stores an event by actorID about targetUserID (admin actions).
	RecordTarget(ctx context.Context, actorID, targetUserID, event string, meta map[string]any)
	List(ctx context.Context, f auditrepo.Filter) ([]*auditrepo.EntryView, error)
}

type AuditService struct {
	Repository auditrepo.AuditRepositoryImpl
}

func NewAuditService(repo auditrepo.AuditRepositoryImpl) AuditServiceImpl {
	return &AuditService{Repository: repo}
}

func (s *AuditService) Record(ctx context.Context, userID, event string, meta map[string]any) {
	s.RecordTarget(ctx, userID, "", event, meta)
}

func (s *AuditService) RecordTarget(ctx context.Context, userID, targetUserID, event string, meta map[string]any) {
	rm := reqmeta.From(ctx)
	if rm.Via != "" {
		// Acting API: the event is the user's, made through another service.
		m := make(map[string]any, len(meta)+1)
		for k, v := range meta {
			m[k] = v
		}
		m["via"] = rm.Via
		meta = m
	}
	e := &auditrepo.Entry{
		ID:    ids.New(ids.Audit),
		Event: event,
		IP:    rm.IP,
		Meta:  repositories.JSONB(meta),
		At:    time.Now().UTC(),
	}
	if userID != "" {
		e.UserID = &userID
	}
	if targetUserID != "" {
		e.TargetUserID = &targetUserID
	}
	if err := s.Repository.Create(ctx, e); err != nil {
		logger.FromCtx(ctx).Error().Err(err).Str("event", event).Msg("audit log write failed")
	}
}

func (s *AuditService) List(ctx context.Context, f auditrepo.Filter) ([]*auditrepo.EntryView, error) {
	return s.Repository.List(ctx, f)
}
