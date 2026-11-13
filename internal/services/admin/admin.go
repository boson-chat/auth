// Package admin holds the operations behind the admin API and CLI.
package admin

import (
	"context"
	"errors"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	auditrepo "github.com/boson-chat/auth/internal/db/repositories/audit"
	inviterepo "github.com/boson-chat/auth/internal/db/repositories/invite"
	sessionrepo "github.com/boson-chat/auth/internal/db/repositories/session"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/services/invite"
	"github.com/boson-chat/auth/internal/services/session"
	"github.com/boson-chat/auth/internal/textutil"
)

const MaxPageSize = 200

type AdminServiceImpl interface {
	ListUsers(ctx context.Context, query string, limit, offset int) ([]*user.User, int64, error)
	GetUser(ctx context.Context, id string) (*user.User, error)
	// FindUser resolves a user id or username (CLI convenience).
	FindUser(ctx context.Context, idOrUsername string) (*user.User, error)
	// SetDisabled disables (revoking every session) or re-enables a user.
	SetDisabled(ctx context.Context, actorID, userID string, disabled bool) (*user.User, error)
	SetRole(ctx context.Context, actorID, userID, role string) (*user.User, error)
	ListSessions(ctx context.Context, userID string) ([]*sessionrepo.Session, error)
	RevokeSession(ctx context.Context, actorID, sessionID string) error
	CreateInvite(ctx context.Context, actorID string, maxUses int, ttl time.Duration, note string) (string, *inviterepo.Invite, error)
	ListInvites(ctx context.Context, limit int) ([]*inviterepo.Invite, error)
	RevokeInvite(ctx context.Context, actorID, id string) error
	ListAudit(ctx context.Context, userID string, limit int) ([]*auditrepo.Entry, error)
}

type AdminService struct {
	Users    user.UserRepositoryImpl
	Tx       db.TxManagerImpl
	Sessions session.SessionServiceImpl
	Invites  invite.InviteServiceImpl
	Audit    audit.AuditServiceImpl
	Now      func() time.Time
}

func NewAdminService(users user.UserRepositoryImpl, tx db.TxManagerImpl, sessions session.SessionServiceImpl,
	invites invite.InviteServiceImpl, auditSvc audit.AuditServiceImpl, now func() time.Time) AdminServiceImpl {
	if now == nil {
		now = time.Now
	}
	return &AdminService{Users: users, Tx: tx, Sessions: sessions, Invites: invites, Audit: auditSvc, Now: now}
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	return min(limit, MaxPageSize)
}

func (s *AdminService) ListUsers(ctx context.Context, query string, limit, offset int) ([]*user.User, int64, error) {
	if !textutil.Storable(query) || len(query) > 254 {
		return nil, 0, apperr.Invalid("invalid query")
	}
	return s.Users.List(ctx, user.ListFilter{Query: query, Limit: clampLimit(limit), Offset: max(offset, 0)})
}

func notFound(err error) error {
	if errors.Is(err, repositories.ErrNotFound) {
		return apperr.ErrNotFound
	}
	return err
}

func (s *AdminService) GetUser(ctx context.Context, id string) (*user.User, error) {
	if !textutil.Storable(id) {
		return nil, apperr.ErrNotFound
	}
	u, err := s.Users.FindByID(ctx, id)
	return u, notFound(err)
}

func (s *AdminService) FindUser(ctx context.Context, idOrUsername string) (*user.User, error) {
	u, err := s.Users.FindByID(ctx, idOrUsername)
	if errors.Is(err, repositories.ErrNotFound) {
		u, err = s.Users.FindByUsernameFolded(ctx, nick.Fold(idOrUsername))
	}
	return u, notFound(err)
}

func (s *AdminService) SetDisabled(ctx context.Context, actorID, userID string, disabled bool) (*user.User, error) {
	var revoked int64
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		var at *time.Time
		if disabled {
			now := s.Now().UTC()
			at = &now
		}
		if err := s.Users.SetDisabled(ctx, userID, at); err != nil {
			return notFound(err)
		}
		if disabled {
			var err error
			revoked, err = s.Sessions.RevokeAll(ctx, userID, "")
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	ev := audit.EventAdminUserEnabled
	if disabled {
		ev = audit.EventAdminUserDisabled
	}
	s.Audit.Record(ctx, actorID, ev, map[string]any{"user_id": userID, "sessions_revoked": revoked})
	return s.GetUser(ctx, userID)
}

func (s *AdminService) SetRole(ctx context.Context, actorID, userID, role string) (*user.User, error) {
	if role != user.RoleUser && role != user.RoleAdmin {
		return nil, apperr.Invalid("role must be user or admin")
	}
	if err := s.Users.SetRole(ctx, userID, role); err != nil {
		return nil, notFound(err)
	}
	s.Audit.Record(ctx, actorID, audit.EventAdminRoleChanged, map[string]any{"user_id": userID, "role": role})
	return s.GetUser(ctx, userID)
}

func (s *AdminService) ListSessions(ctx context.Context, userID string) ([]*sessionrepo.Session, error) {
	return s.Sessions.ListActive(ctx, userID)
}

func (s *AdminService) RevokeSession(ctx context.Context, actorID, sessionID string) error {
	sess, err := s.Sessions.Get(ctx, sessionID)
	if err != nil {
		return err
	}
	if err := s.Sessions.Revoke(ctx, "", sessionID); err != nil {
		return err
	}
	s.Audit.Record(ctx, actorID, audit.EventAdminSessionRevoked, map[string]any{"session_id": sessionID, "user_id": sess.UserID})
	return nil
}

func (s *AdminService) CreateInvite(ctx context.Context, actorID string, maxUses int, ttl time.Duration, note string) (string, *inviterepo.Invite, error) {
	code, inv, err := s.Invites.Create(ctx, actorID, maxUses, ttl, note)
	if err != nil {
		return "", nil, err
	}
	s.Audit.Record(ctx, actorID, audit.EventAdminInviteCreated, map[string]any{"invite_id": inv.ID, "max_uses": maxUses})
	return code, inv, nil
}

func (s *AdminService) ListInvites(ctx context.Context, limit int) ([]*inviterepo.Invite, error) {
	return s.Invites.List(ctx, clampLimit(limit))
}

func (s *AdminService) RevokeInvite(ctx context.Context, actorID, id string) error {
	if err := s.Invites.Revoke(ctx, id); err != nil {
		return err
	}
	s.Audit.Record(ctx, actorID, audit.EventAdminInviteRevoked, map[string]any{"invite_id": id})
	return nil
}

func (s *AdminService) ListAudit(ctx context.Context, userID string, limit int) ([]*auditrepo.Entry, error) {
	if userID != "" {
		return s.Audit.ListByUser(ctx, userID, clampLimit(limit))
	}
	return s.Audit.ListRecent(ctx, clampLimit(limit))
}
