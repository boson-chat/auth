// Package session manages login sessions and their rotating refresh tokens.
//
// Each session has one refresh-token family. Every refresh marks the
// presented token used and issues a new one in the same family. Presenting a
// token that was already used means it was copied: the whole family and the
// session are revoked (reuse detection), so both the thief and the victim
// have to log in again.
package session

import (
	"context"
	"errors"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/refreshtoken"
	sessionrepo "github.com/boson-chat/auth/internal/db/repositories/session"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/opaque"
	"github.com/boson-chat/auth/internal/reqmeta"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/textutil"
	"github.com/boson-chat/auth/metrics"
)

// RefreshTokenPrefix marks our refresh tokens (helps secret scanners).
const RefreshTokenPrefix = "bsr_"

const (
	MethodPassword = "password"
	maxUserAgent   = 512
	// ActivityInterval throttles users.last_active_at: a refresh writes it
	// only when the stored value is at least this old.
	ActivityInterval = 5 * time.Minute
)

// ErrRefreshReuse is returned (wrapped in apperr.ErrInvalidRefresh for
// clients) when an already-used refresh token is presented.
var ErrRefreshReuse = errors.New("session: refresh token reuse detected")

// Issued is a session plus the refresh token handed to the client.
type Issued struct {
	Session          *sessionrepo.Session
	RefreshToken     string
	RefreshExpiresAt time.Time
}

type SessionServiceImpl interface {
	Create(ctx context.Context, userID, method string) (*Issued, error)
	// Refresh rotates a refresh token. Returns apperr.ErrInvalidRefresh for
	// unknown/expired/revoked tokens (errors.Is ErrRefreshReuse on reuse) and
	// apperr.ErrAccountDisabled for disabled users.
	Refresh(ctx context.Context, raw string) (*Issued, *user.User, error)
	// Validate checks that the session is active and belongs to userID, and
	// returns the (enabled) user.
	Validate(ctx context.Context, sessionID, userID string) (*user.User, error)
	Get(ctx context.Context, sessionID string) (*sessionrepo.Session, error)
	ListActive(ctx context.Context, userID string) ([]*sessionrepo.Session, error)
	// Revoke revokes one session; ownerID "" skips the ownership check (admin).
	Revoke(ctx context.Context, ownerID, sessionID string) error
	RevokeAll(ctx context.Context, userID, exceptSessionID string) (int64, error)
	// RevokeByRefreshToken revokes the session a refresh token belongs to
	// (logout without a valid access token). Unknown tokens are ignored.
	RevokeByRefreshToken(ctx context.Context, raw string) (userID, sessionID string, err error)
	// Cleanup deletes long-expired sessions and tokens.
	Cleanup(ctx context.Context) error
}

type Options struct {
	RefreshTTL    time.Duration
	SessionMaxAge time.Duration
	Now           func() time.Time
}

type SessionService struct {
	Sessions      sessionrepo.SessionRepositoryImpl
	RefreshTokens refreshtoken.RefreshTokenRepositoryImpl
	Users         user.UserRepositoryImpl
	Tx            db.TxManagerImpl
	Audit         audit.AuditServiceImpl
	Metrics       *metrics.Metrics
	opts          Options
}

func NewSessionService(
	sessions sessionrepo.SessionRepositoryImpl,
	tokens refreshtoken.RefreshTokenRepositoryImpl,
	users user.UserRepositoryImpl,
	tx db.TxManagerImpl,
	auditSvc audit.AuditServiceImpl,
	m *metrics.Metrics,
	opts Options,
) SessionServiceImpl {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &SessionService{Sessions: sessions, RefreshTokens: tokens, Users: users, Tx: tx, Audit: auditSvc, Metrics: m, opts: opts}
}

func (s *SessionService) now() time.Time { return s.opts.Now().UTC() }

func clientMeta(ctx context.Context) (string, string) {
	m := reqmeta.From(ctx)
	return textutil.Clean(m.IP, 64), textutil.Clean(m.UserAgent, maxUserAgent)
}

func (s *SessionService) newRefresh(ctx context.Context, sess *sessionrepo.Session, familyID string, now time.Time) (string, time.Time, error) {
	raw := opaque.New(RefreshTokenPrefix)
	exp := now.Add(s.opts.RefreshTTL)
	if sess.ExpiresAt.Before(exp) {
		exp = sess.ExpiresAt
	}
	err := s.RefreshTokens.Create(ctx, &refreshtoken.RefreshToken{
		ID:        ids.New(ids.RefreshToken),
		SessionID: sess.ID,
		FamilyID:  familyID,
		TokenHash: opaque.Hash(raw),
		ExpiresAt: exp,
		CreatedAt: now,
	})
	return raw, exp, err
}

func (s *SessionService) Create(ctx context.Context, userID, method string) (*Issued, error) {
	now := s.now()
	ip, ua := clientMeta(ctx)
	sess := &sessionrepo.Session{
		ID:         ids.New(ids.Session),
		UserID:     userID,
		AuthMethod: method,
		IP:         ip,
		UserAgent:  ua,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(s.opts.SessionMaxAge),
	}
	out := &Issued{Session: sess}
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		// User row first, then sessions: the same lock order as disabling a
		// user (which revokes their sessions).
		if err := s.Users.RecordSignIn(ctx, userID, now, method, ip); err != nil {
			return err
		}
		if err := s.Sessions.Create(ctx, sess); err != nil {
			return err
		}
		raw, exp, err := s.newRefresh(ctx, sess, ids.New(ids.TokenFamily), now)
		out.RefreshToken, out.RefreshExpiresAt = raw, exp
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SessionService) Refresh(ctx context.Context, raw string) (*Issued, *user.User, error) {
	if raw == "" {
		s.Metrics.Refresh(ctx, metrics.OutcomeInvalid)
		return nil, nil, apperr.ErrInvalidRefresh
	}
	hash := opaque.Hash(raw)
	var (
		out      *Issued
		u        *user.User
		outcome  = metrics.OutcomeSuccess
		reuse    *refreshtoken.RefreshToken
		disabled bool
	)
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		// Lock order everywhere: session row, then its refresh tokens.
		peek, err := s.RefreshTokens.FindByHash(ctx, hash)
		if errors.Is(err, repositories.ErrNotFound) {
			outcome = metrics.OutcomeInvalid
			return nil
		}
		if err != nil {
			return err
		}
		sess, err := s.Sessions.FindByIDForUpdate(ctx, peek.SessionID)
		if errors.Is(err, repositories.ErrNotFound) {
			outcome = metrics.OutcomeInvalid
			return nil
		}
		if err != nil {
			return err
		}
		tok, err := s.RefreshTokens.FindByHashForUpdate(ctx, hash)
		if err != nil {
			return err
		}
		now := s.now()
		switch {
		case tok.UsedAt != nil:
			outcome = metrics.OutcomeReuse
			reuse = tok
			if err := s.RefreshTokens.RevokeFamily(ctx, tok.FamilyID, now); err != nil {
				return err
			}
			_, err := s.Sessions.Revoke(ctx, sess.ID, now)
			return err
		case tok.RevokedAt != nil, !sess.Active(now):
			outcome = metrics.OutcomeInvalid
			return nil
		case !now.Before(tok.ExpiresAt):
			outcome = metrics.OutcomeExpired
			return nil
		}
		u, err = s.Users.FindByID(ctx, sess.UserID)
		if err != nil {
			return err
		}
		if u.Disabled() {
			outcome, disabled = metrics.OutcomeDisabled, true
			if _, err := s.Sessions.Revoke(ctx, sess.ID, now); err != nil {
				return err
			}
			return s.RefreshTokens.RevokeBySession(ctx, sess.ID, now)
		}
		if err := s.RefreshTokens.MarkUsed(ctx, tok.ID, now); err != nil {
			return err
		}
		ip, ua := clientMeta(ctx)
		if err := s.Sessions.Touch(ctx, sess.ID, now, ip, ua); err != nil {
			return err
		}
		sess.LastSeenAt, sess.IP, sess.UserAgent = now, ip, ua
		newRaw, exp, err := s.newRefresh(ctx, sess, tok.FamilyID, now)
		if err != nil {
			return err
		}
		out = &Issued{Session: sess, RefreshToken: newRaw, RefreshExpiresAt: exp}
		return nil
	})
	if err != nil {
		s.Metrics.Refresh(ctx, metrics.OutcomeError)
		return nil, nil, err
	}
	s.Metrics.Refresh(ctx, outcome)
	if out != nil {
		s.touchActive(ctx, u, out.Session.LastSeenAt)
	}
	switch {
	case reuse != nil:
		logger.FromCtx(ctx).Warn().Str("session_id", reuse.SessionID).Str("family_id", reuse.FamilyID).
			Msg("refresh token reuse: family and session revoked")
		uid := ""
		if sess, err := s.Sessions.FindByID(ctx, reuse.SessionID); err == nil {
			uid = sess.UserID
		}
		s.Audit.Record(ctx, uid, audit.EventRefreshReuse, map[string]any{"session_id": reuse.SessionID, "family_id": reuse.FamilyID})
		return nil, nil, errors.Join(apperr.ErrInvalidRefresh, ErrRefreshReuse)
	case disabled:
		return nil, nil, apperr.ErrAccountDisabled
	case out == nil:
		return nil, nil, apperr.ErrInvalidRefresh
	}
	return out, u, nil
}

// touchActive bumps users.last_active_at alongside sessions.last_seen_at,
// at most once per ActivityInterval. It runs after the refresh transaction
// (which holds the session row lock) so it never takes the user row lock
// in the opposite order to disabling a user; failure only costs accuracy.
func (s *SessionService) touchActive(ctx context.Context, u *user.User, at time.Time) {
	if u.LastActiveAt != nil && at.Sub(*u.LastActiveAt) < ActivityInterval {
		return // fresh enough: skip the query entirely
	}
	wrote, err := s.Users.TouchActive(ctx, u.ID, at, ActivityInterval)
	if err != nil {
		logger.FromCtx(ctx).Warn().Err(err).Str("user_id", u.ID).Msg("last_active_at update failed")
		return
	}
	if wrote {
		u.LastActiveAt = &at
	}
}

func (s *SessionService) Validate(ctx context.Context, sessionID, userID string) (*user.User, error) {
	if !textutil.Storable(sessionID) || !textutil.Storable(userID) {
		return nil, apperr.ErrUnauthenticated
	}
	sess, err := s.Sessions.FindByID(ctx, sessionID)
	if errors.Is(err, repositories.ErrNotFound) {
		return nil, apperr.ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	if sess.UserID != userID || !sess.Active(s.now()) {
		return nil, apperr.ErrUnauthenticated
	}
	u, err := s.Users.FindByID(ctx, userID)
	if errors.Is(err, repositories.ErrNotFound) {
		return nil, apperr.ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	if u.Disabled() {
		return nil, apperr.ErrAccountDisabled
	}
	return u, nil
}

func (s *SessionService) Get(ctx context.Context, sessionID string) (*sessionrepo.Session, error) {
	if !textutil.Storable(sessionID) {
		return nil, apperr.ErrNotFound
	}
	sess, err := s.Sessions.FindByID(ctx, sessionID)
	if errors.Is(err, repositories.ErrNotFound) {
		return nil, apperr.ErrNotFound
	}
	return sess, err
}

func (s *SessionService) ListActive(ctx context.Context, userID string) ([]*sessionrepo.Session, error) {
	return s.Sessions.ListActiveByUser(ctx, userID, s.now())
}

func (s *SessionService) Revoke(ctx context.Context, ownerID, sessionID string) error {
	err := s.revoke(ctx, ownerID, sessionID)
	if err == nil && ownerID != "" {
		s.Audit.Record(ctx, ownerID, audit.EventSessionRevoked, map[string]any{"session_id": sessionID})
	}
	return err
}

func (s *SessionService) revoke(ctx context.Context, ownerID, sessionID string) error {
	if !textutil.Storable(sessionID) {
		return apperr.ErrNotFound
	}
	return s.Tx.WithTx(ctx, func(ctx context.Context) error {
		sess, err := s.Sessions.FindByIDForUpdate(ctx, sessionID)
		if errors.Is(err, repositories.ErrNotFound) {
			return apperr.ErrNotFound
		}
		if err != nil {
			return err
		}
		// Someone else's session looks exactly like a missing one.
		if ownerID != "" && sess.UserID != ownerID {
			return apperr.ErrNotFound
		}
		now := s.now()
		if _, err := s.Sessions.Revoke(ctx, sess.ID, now); err != nil {
			return err
		}
		return s.RefreshTokens.RevokeBySession(ctx, sess.ID, now)
	})
}

func (s *SessionService) RevokeAll(ctx context.Context, userID, exceptSessionID string) (int64, error) {
	var n int64
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		now := s.now()
		var err error
		if n, err = s.Sessions.RevokeAllForUser(ctx, userID, exceptSessionID, now); err != nil {
			return err
		}
		return s.RefreshTokens.RevokeByUser(ctx, userID, exceptSessionID, now)
	})
	return n, err
}

func (s *SessionService) RevokeByRefreshToken(ctx context.Context, raw string) (string, string, error) {
	if raw == "" {
		return "", "", nil
	}
	t, err := s.RefreshTokens.FindByHash(ctx, opaque.Hash(raw))
	if errors.Is(err, repositories.ErrNotFound) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	sess, err := s.Sessions.FindByID(ctx, t.SessionID)
	if errors.Is(err, repositories.ErrNotFound) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	if err := s.revoke(ctx, "", sess.ID); err != nil && !errors.Is(err, apperr.ErrNotFound) {
		return "", "", err
	}
	return sess.UserID, sess.ID, nil
}

// cleanupGrace keeps expired rows around for a while for forensics.
const cleanupGrace = 30 * 24 * time.Hour

func (s *SessionService) Cleanup(ctx context.Context) error {
	before := s.now().Add(-cleanupGrace)
	if _, err := s.RefreshTokens.DeleteExpiredBefore(ctx, before); err != nil {
		return err
	}
	_, err := s.Sessions.DeleteExpiredBefore(ctx, before)
	return err
}
