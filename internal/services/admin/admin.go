// Package admin holds the operations behind the admin API and CLI.
package admin

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	auditrepo "github.com/boson-chat/auth/internal/db/repositories/audit"
	inviterepo "github.com/boson-chat/auth/internal/db/repositories/invite"
	"github.com/boson-chat/auth/internal/db/repositories/role"
	sessionrepo "github.com/boson-chat/auth/internal/db/repositories/session"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/services/account"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/services/invite"
	"github.com/boson-chat/auth/internal/services/roles"
	"github.com/boson-chat/auth/internal/services/session"
	"github.com/boson-chat/auth/internal/textutil"
)

const MaxPageSize = 200

// CreateUserInput is POST /v1/admin/users. The email (if any) is marked
// verified. Password and SendSetupEmail are mutually exclusive; with neither
// the account has no password until a reset (or SSO).
type CreateUserInput struct {
	Username string
	Email    string
	// Role: user (default), admin or owner. Giving admin/owner needs
	// roles.manage and must respect the role hierarchy.
	Role           string
	Password       string
	SendSetupEmail bool
}

// AuditQuery filters GET /v1/admin/audit. Actor and Target take a user id
// or a username. Cursor is the next_cursor of the previous page.
type AuditQuery struct {
	Events []string
	Actor  string
	Target string
	UserID string // actor or target (legacy ?user_id=)
	Since  *time.Time
	Until  *time.Time
	Cursor string
	Limit  int
}

var errBadCursor = apperr.Invalid("invalid cursor")

// Delivery is how a password reset / account setup link reached the user:
// emailed (Sent), or, without a mail server, Link for the admin to copy.
type Delivery struct {
	Sent bool
	Link string
}

type AdminServiceImpl interface {
	// CreateUser creates an account (email verified) and optionally emails a
	// "choose your password" link (without a mail server: returns the link
	// for the admin to hand over).
	CreateUser(ctx context.Context, actorID string, in CreateUserInput) (*user.User, Delivery, error)
	// SendPasswordReset emails the user a reset link (same flow as forgot),
	// or returns it without a mail server.
	SendPasswordReset(ctx context.Context, actorID, userID string) (Delivery, error)
	// SendVerification emails the user a new verification link.
	SendVerification(ctx context.Context, actorID, userID string) error
	// ListUsers searches users; sort is a user.Sort* value ("" = created).
	ListUsers(ctx context.Context, query, sort string, limit, offset int) ([]*user.User, int64, error)
	GetUser(ctx context.Context, id string) (*user.User, error)
	// FindUser resolves a user id or username (CLI convenience).
	FindUser(ctx context.Context, idOrUsername string) (*user.User, error)
	// SetDisabled disables (revoking every session) or re-enables a user
	// ranked below the actor.
	SetDisabled(ctx context.Context, actorID, userID string, disabled bool) (*user.User, error)
	// SetRole is the 1.x role switch (user | admin | owner), mapped onto roles.
	SetRole(ctx context.Context, actorID, userID, role string) (*user.User, error)
	ListSessions(ctx context.Context, userID string) ([]*sessionrepo.Session, error)
	RevokeSession(ctx context.Context, actorID, sessionID string) error
	CreateInvite(ctx context.Context, actorID string, maxUses int, ttl time.Duration, note string) (string, *inviterepo.Invite, error)
	ListInvites(ctx context.Context, limit int) ([]*inviterepo.Invite, error)
	RevokeInvite(ctx context.Context, actorID, id string) error
	// ListAudit returns one page, newest first, and the cursor of the next
	// page ("" on the last page).
	ListAudit(ctx context.Context, q AuditQuery) ([]*auditrepo.EntryView, string, error)
}

type AdminService struct {
	Account  account.AccountServiceImpl
	Users    user.UserRepositoryImpl
	Tx       db.TxManagerImpl
	Sessions session.SessionServiceImpl
	Invites  invite.InviteServiceImpl
	Audit    audit.AuditServiceImpl
	Roles    roles.RolesServiceImpl
	Now      func() time.Time
}

func NewAdminService(acct account.AccountServiceImpl, users user.UserRepositoryImpl, tx db.TxManagerImpl, sessions session.SessionServiceImpl,
	invites invite.InviteServiceImpl, auditSvc audit.AuditServiceImpl, rolesSvc roles.RolesServiceImpl, now func() time.Time) AdminServiceImpl {
	if now == nil {
		now = time.Now
	}
	return &AdminService{Account: acct, Users: users, Tx: tx, Sessions: sessions, Invites: invites, Audit: auditSvc, Roles: rolesSvc, Now: now}
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	return min(limit, MaxPageSize)
}

func (s *AdminService) ListUsers(ctx context.Context, query, sort string, limit, offset int) ([]*user.User, int64, error) {
	if !textutil.Storable(query) || len(query) > 254 {
		return nil, 0, apperr.Invalid("invalid query")
	}
	if !user.ValidSort(sort) {
		return nil, 0, apperr.Invalid("sort must be created, last_active or last_sign_in")
	}
	return s.Users.List(ctx, user.ListFilter{Query: query, Sort: sort, Limit: clampLimit(limit), Offset: max(offset, 0)})
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
	if _, err := s.GetUser(ctx, userID); err != nil {
		return nil, err
	}
	if err := s.Roles.CheckManageUser(ctx, actorID, userID); err != nil {
		return nil, err
	}
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
	s.Audit.RecordTarget(ctx, actorID, userID, ev, map[string]any{"user_id": userID, "sessions_revoked": revoked})
	return s.GetUser(ctx, userID)
}

func (s *AdminService) SetRole(ctx context.Context, actorID, userID, legacy string) (*user.User, error) {
	if err := s.Roles.SetLegacyRole(ctx, actorID, userID, legacy); err != nil {
		return nil, err
	}
	s.Audit.RecordTarget(ctx, actorID, userID, audit.EventAdminRoleChanged, map[string]any{"user_id": userID, "role": legacy})
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
	if err := s.Roles.CheckManageUser(ctx, actorID, sess.UserID); err != nil {
		return err
	}
	if err := s.Sessions.Revoke(ctx, "", sessionID); err != nil {
		return err
	}
	s.Audit.RecordTarget(ctx, actorID, sess.UserID, audit.EventAdminSessionRevoked, map[string]any{"session_id": sessionID, "user_id": sess.UserID})
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

func (s *AdminService) CreateUser(ctx context.Context, actorID string, in CreateUserInput) (*user.User, Delivery, error) {
	if in.Password != "" && in.SendSetupEmail {
		return nil, Delivery{}, apperr.Invalid("give either password or send_invite_email, not both")
	}
	if in.SendSetupEmail && strings.TrimSpace(in.Email) == "" {
		return nil, Delivery{}, apperr.Invalid("send_invite_email needs an email address")
	}
	switch in.Role {
	case "", user.RoleUser:
	case user.RoleAdmin:
		if err := s.Roles.CheckAssign(ctx, actorID, role.AdminID); err != nil {
			return nil, Delivery{}, err
		}
	case role.BuiltinOwner:
		if err := s.Roles.CheckAssign(ctx, actorID, role.OwnerID); err != nil {
			return nil, Delivery{}, err
		}
	default:
		return nil, Delivery{}, apperr.Invalid("role must be user, admin or owner")
	}
	u, err := s.Account.CreateUser(ctx, actorID, account.CreateUserInput{
		Username: in.Username, Email: in.Email, Password: in.Password, Role: in.Role, EmailVerified: true,
	})
	if err != nil {
		return nil, Delivery{}, err
	}
	if !in.SendSetupEmail {
		return u, Delivery{}, nil
	}
	link, err := s.Account.SendPasswordReset(ctx, u.ID, true)
	if err != nil {
		return u, Delivery{}, err
	}
	return u, Delivery{Sent: link == "", Link: link}, nil
}

func (s *AdminService) SendPasswordReset(ctx context.Context, actorID, userID string) (Delivery, error) {
	link, err := s.Account.SendPasswordReset(ctx, userID, false)
	if err != nil {
		return Delivery{}, err
	}
	meta := map[string]any{"user_id": userID}
	if link != "" {
		meta["delivery"] = "link" // handed to the admin, not emailed
	}
	s.Audit.RecordTarget(ctx, actorID, userID, audit.EventAdminResetSent, meta)
	return Delivery{Sent: link == "", Link: link}, nil
}

func (s *AdminService) SendVerification(ctx context.Context, actorID, userID string) error {
	if err := s.Account.SendVerification(ctx, userID); err != nil {
		return err
	}
	s.Audit.RecordTarget(ctx, actorID, userID, audit.EventAdminVerifySent, map[string]any{"user_id": userID})
	return nil
}

// EncodeCursor and DecodeCursor make the opaque next_cursor of audit pages.
func EncodeCursor(c auditrepo.Cursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(c.At.UTC().Format(time.RFC3339Nano) + "|" + c.ID))
}

func DecodeCursor(s string) (auditrepo.Cursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return auditrepo.Cursor{}, errBadCursor
	}
	at, id, ok := strings.Cut(string(b), "|")
	if !ok || !ids.HasPrefix(id, ids.Audit) {
		return auditrepo.Cursor{}, errBadCursor
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return auditrepo.Cursor{}, errBadCursor
	}
	return auditrepo.Cursor{At: t, ID: id}, nil
}

// resolveUser maps a user id or username to an id. ok is false when no such
// user exists (the filter then matches nothing).
func (s *AdminService) resolveUser(ctx context.Context, v string) (string, bool, error) {
	if !textutil.Storable(v) || len(v) > 64 {
		return "", false, apperr.Invalid("invalid user filter")
	}
	if ids.HasPrefix(v, ids.User) {
		return v, true, nil
	}
	u, err := s.Users.FindByUsernameFolded(ctx, nick.Fold(v))
	if errors.Is(err, repositories.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return u.ID, true, nil
}

func (s *AdminService) ListAudit(ctx context.Context, q AuditQuery) ([]*auditrepo.EntryView, string, error) {
	f := auditrepo.Filter{Since: q.Since, Until: q.Until, Limit: clampLimit(q.Limit)}
	for _, ev := range q.Events {
		if ev = strings.TrimSpace(ev); ev != "" {
			if !textutil.Storable(ev) || len(ev) > 64 {
				return nil, "", apperr.Invalid("invalid event filter")
			}
			f.Events = append(f.Events, ev)
		}
	}
	for _, p := range []struct {
		in  string
		out *string
	}{{q.Actor, &f.ActorID}, {q.Target, &f.TargetID}, {q.UserID, &f.AnyUserID}} {
		if p.in == "" {
			continue
		}
		id, ok, err := s.resolveUser(ctx, p.in)
		if err != nil {
			return nil, "", err
		}
		if !ok {
			return []*auditrepo.EntryView{}, "", nil
		}
		*p.out = id
	}
	if q.Cursor != "" {
		c, err := DecodeCursor(q.Cursor)
		if err != nil {
			return nil, "", err
		}
		f.After = &c
	}
	// Fetch one extra row to know whether another page exists.
	want := f.Limit
	f.Limit++
	list, err := s.Audit.List(ctx, f)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(list) > want {
		list = list[:want]
		last := list[want-1]
		next = EncodeCursor(auditrepo.Cursor{At: last.At, ID: last.ID})
	}
	return list, next, nil
}
