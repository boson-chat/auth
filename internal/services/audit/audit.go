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
)

type AuditServiceImpl interface {
	// Record stores an event. userID may be "" (unknown user).
	Record(ctx context.Context, userID, event string, meta map[string]any)
	ListByUser(ctx context.Context, userID string, limit int) ([]*auditrepo.Entry, error)
	ListRecent(ctx context.Context, limit int) ([]*auditrepo.Entry, error)
}

type AuditService struct {
	Repository auditrepo.AuditRepositoryImpl
}

func NewAuditService(repo auditrepo.AuditRepositoryImpl) AuditServiceImpl {
	return &AuditService{Repository: repo}
}

func (s *AuditService) Record(ctx context.Context, userID, event string, meta map[string]any) {
	e := &auditrepo.Entry{
		ID:    ids.New(ids.Audit),
		Event: event,
		IP:    reqmeta.From(ctx).IP,
		Meta:  repositories.JSONB(meta),
		At:    time.Now().UTC(),
	}
	if userID != "" {
		e.UserID = &userID
	}
	if err := s.Repository.Create(ctx, e); err != nil {
		logger.FromCtx(ctx).Error().Err(err).Str("event", event).Msg("audit log write failed")
	}
}

func (s *AuditService) ListByUser(ctx context.Context, userID string, limit int) ([]*auditrepo.Entry, error) {
	return s.Repository.ListByUser(ctx, userID, limit)
}

func (s *AuditService) ListRecent(ctx context.Context, limit int) ([]*auditrepo.Entry, error) {
	return s.Repository.ListRecent(ctx, limit)
}
