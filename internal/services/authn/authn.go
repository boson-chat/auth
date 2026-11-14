// Package authn handles password login, token refresh, logout, request
// authentication, voice tokens and the internal password check used by IRC
// SASL.
package authn

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/credential"
	sessionrepo "github.com/boson-chat/auth/internal/db/repositories/session"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/password"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/services/session"
	"github.com/boson-chat/auth/internal/services/settings"
	"github.com/boson-chat/auth/internal/services/token"
	"github.com/boson-chat/auth/internal/textutil"
	"github.com/boson-chat/auth/metrics"
)

const (
	maxRooms   = 32
	maxRoomLen = 128
)

// Principal is the authenticated caller of a request.
type Principal struct {
	UserID    string
	SessionID string
	// User is loaded fresh from the database on every request, so role and
	// disabled state never come from a (possibly stale) token.
	User *user.User
}

func (p *Principal) IsAdmin() bool { return p.User.Role == user.RoleAdmin }

// Tokens is the result of a login or refresh.
type Tokens struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
	Session          *sessionrepo.Session
	User             *user.User
}

type AuthnServiceImpl interface {
	Login(ctx context.Context, login, pw string) (*Tokens, error)
	// IssueSession signs in a user who authenticated elsewhere (SSO):
	// method is "oidc:<slug>" or "saml:<slug>". Disabled users are refused.
	IssueSession(ctx context.Context, u *user.User, method string) (*Tokens, error)
	Refresh(ctx context.Context, refreshToken string) (*Tokens, error)
	Logout(ctx context.Context, p *Principal) error
	Authenticate(ctx context.Context, accessToken string) (*Principal, error)
	VoiceToken(ctx context.Context, p *Principal, rooms []string) (string, time.Time, error)
	// VerifyPassword checks username + password without creating a session
	// (IRC SASL PLAIN via the internal API).
	VerifyPassword(ctx context.Context, username, pw string) (*user.User, error)
}

type Deps struct {
	Users       user.UserRepositoryImpl
	Credentials credential.CredentialRepositoryImpl
	Sessions    session.SessionServiceImpl
	Tokens      token.TokenServiceImpl
	Audit       audit.AuditServiceImpl
	Hasher      *password.Hasher
	Metrics     *metrics.Metrics
	// Settings.require_email_verification blocks password login until the
	// email is verified.
	Settings settings.SettingsServiceImpl
}

type AuthnService struct {
	Deps
}

func NewAuthnService(d Deps) AuthnServiceImpl {
	return &AuthnService{Deps: d}
}

// findLogin looks a user up by email (contains @; usernames never do) or by
// folded username.
func (s *AuthnService) findLogin(ctx context.Context, login string) (*user.User, error) {
	login = strings.TrimSpace(login)
	if login == "" || len(login) > 320 || !textutil.Storable(login) {
		return nil, repositories.ErrNotFound
	}
	if strings.Contains(login, "@") {
		return s.Users.FindByEmail(ctx, login)
	}
	return s.Users.FindByUsernameFolded(ctx, nick.Fold(login))
}

// checkPassword returns the user if pw is right, burning the same argon2
// time whether or not the account (or its password) exists. It reports
// disabled / unverified only after the password has been proven.
func (s *AuthnService) checkPassword(ctx context.Context, method string, u *user.User, lookupErr error, pw string) (*user.User, error) {
	fail := func(reason string, userID string) (*user.User, error) {
		s.Metrics.LoginAttempt(ctx, method, metrics.OutcomeInvalidCredentials)
		s.Audit.Record(ctx, userID, audit.EventLoginFailed, map[string]any{"reason": reason, "method": method})
		return nil, apperr.ErrInvalidCredentials
	}
	if lookupErr != nil && !errors.Is(lookupErr, repositories.ErrNotFound) {
		return nil, lookupErr
	}
	if len(pw) > 4*password.MaxLength { // don't hash megabytes
		s.Hasher.VerifyDummy("")
		return fail("password_too_long", "")
	}
	if u == nil {
		s.Hasher.VerifyDummy(pw)
		return fail("unknown_user", "")
	}
	cred, err := s.Credentials.Get(ctx, u.ID)
	if errors.Is(err, repositories.ErrNotFound) {
		s.Hasher.VerifyDummy(pw)
		return fail("no_password", u.ID)
	}
	if err != nil {
		return nil, err
	}
	ok, rehash, err := s.Hasher.Verify(pw, cred.Hash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return fail("wrong_password", u.ID)
	}
	if rehash {
		if h, err := s.Hasher.Hash(pw); err == nil {
			if err := s.Credentials.Upsert(ctx, u.ID, h); err != nil {
				logger.FromCtx(ctx).Warn().Err(err).Str("user_id", u.ID).Msg("password rehash failed")
			}
		}
	}
	if u.Disabled() {
		s.Metrics.LoginAttempt(ctx, method, metrics.OutcomeDisabled)
		s.Audit.Record(ctx, u.ID, audit.EventLoginFailed, map[string]any{"reason": "disabled", "method": method})
		return nil, apperr.ErrAccountDisabled
	}
	st, err := s.Settings.Get(ctx)
	if err != nil {
		return nil, err
	}
	if st.RequireEmailVerification && !u.EmailVerified() {
		s.Metrics.LoginAttempt(ctx, method, metrics.OutcomeUnverified)
		return nil, apperr.ErrEmailNotVerified
	}
	return u, nil
}

func (s *AuthnService) Login(ctx context.Context, login, pw string) (*Tokens, error) {
	u, err := s.findLogin(ctx, login)
	if err != nil {
		u = nil
	}
	u, err = s.checkPassword(ctx, session.MethodPassword, u, err, pw)
	if err != nil {
		return nil, err
	}
	issued, err := s.Sessions.Create(ctx, u.ID, session.MethodPassword)
	if err != nil {
		return nil, err
	}
	access, exp, err := s.Tokens.MintAccess(ctx, u, issued.Session.ID)
	if err != nil {
		return nil, err
	}
	s.Metrics.LoginAttempt(ctx, session.MethodPassword, metrics.OutcomeSuccess)
	s.Audit.Record(ctx, u.ID, audit.EventLogin, map[string]any{"method": session.MethodPassword, "session_id": issued.Session.ID})
	return &Tokens{
		AccessToken: access, AccessExpiresAt: exp,
		RefreshToken: issued.RefreshToken, RefreshExpiresAt: issued.RefreshExpiresAt,
		Session: issued.Session, User: u,
	}, nil
}

func (s *AuthnService) IssueSession(ctx context.Context, u *user.User, method string) (*Tokens, error) {
	kind, _, _ := strings.Cut(method, ":")
	if u.Disabled() {
		s.Metrics.LoginAttempt(ctx, kind, metrics.OutcomeDisabled)
		s.Audit.Record(ctx, u.ID, audit.EventLoginFailed, map[string]any{"reason": "disabled", "method": method})
		return nil, apperr.ErrAccountDisabled
	}
	issued, err := s.Sessions.Create(ctx, u.ID, method)
	if err != nil {
		return nil, err
	}
	access, exp, err := s.Tokens.MintAccess(ctx, u, issued.Session.ID)
	if err != nil {
		return nil, err
	}
	s.Metrics.LoginAttempt(ctx, kind, metrics.OutcomeSuccess)
	s.Audit.Record(ctx, u.ID, audit.EventLogin, map[string]any{"method": method, "session_id": issued.Session.ID})
	return &Tokens{
		AccessToken: access, AccessExpiresAt: exp,
		RefreshToken: issued.RefreshToken, RefreshExpiresAt: issued.RefreshExpiresAt,
		Session: issued.Session, User: u,
	}, nil
}

func (s *AuthnService) Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	issued, u, err := s.Sessions.Refresh(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	access, exp, err := s.Tokens.MintAccess(ctx, u, issued.Session.ID)
	if err != nil {
		return nil, err
	}
	return &Tokens{
		AccessToken: access, AccessExpiresAt: exp,
		RefreshToken: issued.RefreshToken, RefreshExpiresAt: issued.RefreshExpiresAt,
		Session: issued.Session, User: u,
	}, nil
}

func (s *AuthnService) Logout(ctx context.Context, p *Principal) error {
	if err := s.Sessions.Revoke(ctx, p.UserID, p.SessionID); err != nil && !errors.Is(err, apperr.ErrNotFound) {
		return err
	}
	s.Audit.Record(ctx, p.UserID, audit.EventLogout, map[string]any{"session_id": p.SessionID})
	return nil
}

func (s *AuthnService) Authenticate(ctx context.Context, accessToken string) (*Principal, error) {
	if accessToken == "" {
		return nil, apperr.ErrUnauthenticated
	}
	c, err := s.Tokens.VerifyAccess(ctx, accessToken)
	if err != nil {
		return nil, apperr.ErrUnauthenticated
	}
	u, err := s.Sessions.Validate(ctx, c.SessionID, c.Subject)
	if err != nil {
		return nil, err
	}
	return &Principal{UserID: u.ID, SessionID: c.SessionID, User: u}, nil
}

func (s *AuthnService) VoiceToken(ctx context.Context, p *Principal, rooms []string) (string, time.Time, error) {
	if len(rooms) > maxRooms {
		return "", time.Time{}, apperr.Invalid("at most 32 rooms")
	}
	clean := make([]string, 0, len(rooms))
	for _, r := range rooms {
		if r == "" || len(r) > maxRoomLen || !utf8.ValidString(r) {
			return "", time.Time{}, apperr.Invalid("room names must be 1-128 bytes of UTF-8")
		}
		clean = append(clean, r)
	}
	return s.Tokens.MintVoice(ctx, p.User, p.SessionID, clean)
}

func (s *AuthnService) VerifyPassword(ctx context.Context, username, pw string) (*user.User, error) {
	var (
		u   *user.User
		err = repositories.ErrNotFound
	)
	if username != "" && len(username) <= nick.MaxLen && textutil.Storable(username) {
		u, err = s.Users.FindByUsernameFolded(ctx, nick.Fold(username))
	}
	if err != nil {
		u = nil
	}
	u, err = s.checkPassword(ctx, "internal", u, err, pw)
	if err != nil {
		return nil, err
	}
	s.Metrics.LoginAttempt(ctx, "internal", metrics.OutcomeSuccess)
	s.Audit.Record(ctx, u.ID, audit.EventInternalVerify, nil)
	return u, nil
}
