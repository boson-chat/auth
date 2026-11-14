// Package account handles registration, email verification, password
// reset/change and profile updates.
package account

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/credential"
	"github.com/boson-chat/auth/internal/db/repositories/emailtoken"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/opaque"
	"github.com/boson-chat/auth/internal/password"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/services/email"
	"github.com/boson-chat/auth/internal/services/invite"
	"github.com/boson-chat/auth/internal/services/session"
	"github.com/boson-chat/auth/internal/services/settings"
	"github.com/boson-chat/auth/internal/textutil"
	"github.com/boson-chat/auth/metrics"
)

const (
	EmailTokenPrefix  = "bse_"
	maxEmailLen       = 254
	maxDisplayNameLen = 64
)

var ErrInvalidPassword = apperr.New(403, "invalid_password", "current password is wrong")

type RegisterInput struct {
	Username   string
	Email      string
	Password   string
	InviteCode string
}

type CreateUserInput struct {
	Username      string
	Email         string
	Password      string // empty = no password credential (SSO-only)
	Role          string
	EmailVerified bool
}

type AccountServiceImpl interface {
	Register(ctx context.Context, in RegisterInput) (*user.User, error)
	// CreateUser is the admin/CLI path: no registration mode or invite checks.
	CreateUser(ctx context.Context, actorID string, in CreateUserInput) (*user.User, error)
	VerifyEmail(ctx context.Context, token string) (*user.User, error)
	// ResendVerification sends a new link to userID's address, or to the
	// account with emailAddr. It reveals nothing: unknown, verified or
	// disabled accounts are silently skipped.
	ResendVerification(ctx context.Context, userID, emailAddr string) error
	// ForgotPassword emails a reset link to the stored address of the account
	// with that email. It always returns nil to clients.
	ForgotPassword(ctx context.Context, emailAddr string) error
	// SendPasswordReset emails userID a reset link (admin action). setup
	// words it as "choose your password" for a new account and uses
	// ACCOUNT_SETUP_TTL. Errors: not_found, no_email, account_disabled.
	SendPasswordReset(ctx context.Context, userID string, setup bool) error
	// SendVerification emails userID a new verification link (admin action).
	// Errors: not_found, no_email, already_verified, account_disabled.
	SendVerification(ctx context.Context, userID string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	ChangePassword(ctx context.Context, userID, keepSessionID, current, newPassword string) error
	Get(ctx context.Context, userID string) (*user.User, error)
	UpdateProfile(ctx context.Context, userID string, displayName *string) (*user.User, error)
	// Cleanup deletes email tokens that expired more than a week ago.
	Cleanup(ctx context.Context) error
}

type Deps struct {
	Users       user.UserRepositoryImpl
	Credentials credential.CredentialRepositoryImpl
	EmailTokens emailtoken.EmailTokenRepositoryImpl
	Tx          db.TxManagerImpl
	Invites     invite.InviteServiceImpl
	Sessions    session.SessionServiceImpl
	Email       email.EmailServiceImpl
	Audit       audit.AuditServiceImpl
	Settings    settings.SettingsServiceImpl
	Hasher      *password.Hasher
	Metrics     *metrics.Metrics
	Config      config.AccountConfig
	Now         func() time.Time
}

type AccountService struct {
	Deps
}

func NewAccountService(d Deps) AccountServiceImpl {
	if d.Now == nil {
		d.Now = time.Now
	}
	return &AccountService{Deps: d}
}

func (s *AccountService) now() time.Time { return s.Now().UTC() }

// NormalizeEmail validates a bare address (no display name).
func NormalizeEmail(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", apperr.Invalid("email is required")
	}
	if len(addr) > maxEmailLen {
		return "", apperr.Invalid("email is too long")
	}
	if !textutil.Storable(addr) {
		return "", apperr.Invalid("email is not a valid address")
	}
	a, err := mail.ParseAddress(addr)
	if err != nil || a.Name != "" || a.Address != addr {
		return "", apperr.Invalid("email is not a valid address")
	}
	at := strings.LastIndexByte(addr, '@')
	if at < 1 || at == len(addr)-1 {
		return "", apperr.Invalid("email is not a valid address")
	}
	return addr, nil
}

// CleanDisplayName trims and validates a display name ("" is allowed).
func CleanDisplayName(n string) (string, error) {
	n = strings.TrimSpace(n)
	if utf8.RuneCountInString(n) > maxDisplayNameLen {
		return "", apperr.Invalid("display_name must be at most 64 characters")
	}
	if !utf8.ValidString(n) || strings.IndexFunc(n, unicode.IsControl) >= 0 {
		return "", apperr.Invalid("display_name contains invalid characters")
	}
	return n, nil
}

func validateIdentity(username, emailAddr, pw string, requirePassword bool) (string, error) {
	if err := nick.Validate(username); err != nil {
		return "", apperr.New(400, "invalid_username", err.Error())
	}
	addr := ""
	if emailAddr != "" || requirePassword {
		var err error
		if addr, err = NormalizeEmail(emailAddr); err != nil {
			return "", err
		}
	}
	if pw != "" || requirePassword {
		if err := password.CheckPolicy(pw, username, addr); err != nil {
			return "", apperr.New(400, "weak_password", err.Error())
		}
	}
	return addr, nil
}

func mapUserErr(err error) error {
	switch {
	case errors.Is(err, user.ErrUsernameTaken):
		return apperr.ErrUsernameTaken
	case errors.Is(err, user.ErrEmailTaken):
		return apperr.ErrEmailTaken
	}
	return err
}

// newEmailToken stores a hashed single-use token and returns the plaintext.
func (s *AccountService) newEmailToken(ctx context.Context, userID, purpose string, ttl time.Duration) (string, error) {
	raw := opaque.New(EmailTokenPrefix)
	now := s.now()
	err := s.EmailTokens.Create(ctx, &emailtoken.EmailToken{
		ID: ids.New(ids.EmailToken), UserID: userID, Purpose: purpose,
		TokenHash: opaque.Hash(raw), ExpiresAt: now.Add(ttl), CreatedAt: now,
	})
	return raw, err
}

func (s *AccountService) Register(ctx context.Context, in RegisterInput) (*user.User, error) {
	st, err := s.Settings.Get(ctx)
	if err != nil {
		return nil, err
	}
	switch st.Registration {
	case config.RegistrationClosed:
		s.Metrics.Registration(ctx, metrics.OutcomeRejected)
		return nil, apperr.ErrRegistrationClosed
	case config.RegistrationInvite:
		if in.InviteCode == "" {
			s.Metrics.Registration(ctx, metrics.OutcomeRejected)
			return nil, apperr.ErrInviteRequired
		}
	}
	addr, err := validateIdentity(in.Username, in.Email, in.Password, true)
	if err != nil {
		s.Metrics.Registration(ctx, metrics.OutcomeRejected)
		return nil, err
	}
	hash, err := s.Hasher.Hash(in.Password)
	if err != nil {
		return nil, err
	}
	now := s.now()
	u := &user.User{
		ID: ids.New(ids.User), Username: in.Username, UsernameFolded: nick.Fold(in.Username),
		Email: &addr, Role: user.RoleUser, CreatedAt: now, UpdatedAt: now,
	}
	var verifyToken string
	err = s.Tx.WithTx(ctx, func(ctx context.Context) error {
		if st.Registration == config.RegistrationInvite {
			if err := s.Invites.Redeem(ctx, in.InviteCode); err != nil {
				return err
			}
		}
		if err := s.Users.Create(ctx, u); err != nil {
			return mapUserErr(err)
		}
		if err := s.Credentials.Upsert(ctx, u.ID, hash); err != nil {
			return err
		}
		verifyToken, err = s.newEmailToken(ctx, u.ID, emailtoken.PurposeVerifyEmail, s.Config.EmailVerifyTTL)
		return err
	})
	if err != nil {
		if _, ok := apperr.As(err); ok {
			s.Metrics.Registration(ctx, metrics.OutcomeRejected)
		} else {
			s.Metrics.Registration(ctx, metrics.OutcomeError)
		}
		return nil, err
	}
	s.Email.SendVerification(ctx, u, verifyToken, s.Config.EmailVerifyTTL)
	s.Metrics.Registration(ctx, metrics.OutcomeSuccess)
	s.Audit.Record(ctx, u.ID, audit.EventRegister, nil)
	return u, nil
}

func (s *AccountService) CreateUser(ctx context.Context, actorID string, in CreateUserInput) (*user.User, error) {
	addr, err := validateIdentity(in.Username, in.Email, in.Password, false)
	if err != nil {
		return nil, err
	}
	role := in.Role
	if role == "" {
		role = user.RoleUser
	}
	if role != user.RoleUser && role != user.RoleAdmin {
		return nil, apperr.Invalid("role must be user or admin")
	}
	hash := ""
	if in.Password != "" {
		if hash, err = s.Hasher.Hash(in.Password); err != nil {
			return nil, err
		}
	}
	now := s.now()
	u := &user.User{
		ID: ids.New(ids.User), Username: in.Username, UsernameFolded: nick.Fold(in.Username),
		Role: role, CreatedAt: now, UpdatedAt: now,
	}
	if addr != "" {
		u.Email = &addr
		if in.EmailVerified {
			u.EmailVerifiedAt = &now
		}
	}
	err = s.Tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.Users.Create(ctx, u); err != nil {
			return mapUserErr(err)
		}
		if hash != "" {
			return s.Credentials.Upsert(ctx, u.ID, hash)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.Audit.RecordTarget(ctx, actorID, u.ID, audit.EventAdminUserCreated, map[string]any{"user_id": u.ID, "role": role})
	return u, nil
}

// consume validates and uses a single-use email token inside a transaction.
func (s *AccountService) consume(ctx context.Context, raw, purpose string) (*emailtoken.EmailToken, error) {
	if raw == "" || len(raw) > 128 {
		return nil, apperr.ErrInvalidToken
	}
	t, err := s.EmailTokens.FindByHashForUpdate(ctx, opaque.Hash(raw), purpose)
	if errors.Is(err, repositories.ErrNotFound) {
		return nil, apperr.ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	if t.UsedAt != nil || !s.now().Before(t.ExpiresAt) {
		return nil, apperr.ErrInvalidToken
	}
	return t, nil
}

func (s *AccountService) VerifyEmail(ctx context.Context, raw string) (*user.User, error) {
	var u *user.User
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		t, err := s.consume(ctx, raw, emailtoken.PurposeVerifyEmail)
		if err != nil {
			return err
		}
		now := s.now()
		if err := s.EmailTokens.ConsumeAllForUser(ctx, t.UserID, emailtoken.PurposeVerifyEmail, now); err != nil {
			return err
		}
		if u, err = s.Users.FindByID(ctx, t.UserID); err != nil {
			return err
		}
		if u.EmailVerifiedAt == nil {
			if err := s.Users.SetEmailVerified(ctx, u.ID, now); err != nil {
				return err
			}
			u.EmailVerifiedAt = &now
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.Audit.Record(ctx, u.ID, audit.EventEmailVerified, nil)
	return u, nil
}

func (s *AccountService) ResendVerification(ctx context.Context, userID, emailAddr string) error {
	var (
		u   *user.User
		err error
	)
	switch {
	case userID != "":
		u, err = s.Users.FindByID(ctx, userID)
	case emailAddr != "":
		addr, nerr := NormalizeEmail(emailAddr)
		if nerr != nil {
			return nerr
		}
		u, err = s.Users.FindByEmail(ctx, addr)
	default:
		return apperr.Invalid("email is required")
	}
	if errors.Is(err, repositories.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if u.EmailVerified() || u.Disabled() || u.Email == nil {
		return nil
	}
	tok, err := s.newEmailToken(ctx, u.ID, emailtoken.PurposeVerifyEmail, s.Config.EmailVerifyTTL)
	if err != nil {
		return err
	}
	s.Email.SendVerification(ctx, u, tok, s.Config.EmailVerifyTTL)
	return nil
}

func (s *AccountService) ForgotPassword(ctx context.Context, emailAddr string) error {
	addr, err := NormalizeEmail(emailAddr)
	if err != nil {
		return err // malformed input is safe to reject: says nothing about accounts
	}
	log := logger.FromCtx(ctx)
	u, err := s.Users.FindByEmail(ctx, addr)
	if err != nil {
		if !errors.Is(err, repositories.ErrNotFound) {
			log.Error().Err(err).Msg("forgot password lookup")
		}
		return nil
	}
	if u.Disabled() {
		return nil
	}
	var tok string
	err = s.Tx.WithTx(ctx, func(ctx context.Context) error {
		// One live reset link at a time.
		if err := s.EmailTokens.ConsumeAllForUser(ctx, u.ID, emailtoken.PurposeResetPassword, s.now()); err != nil {
			return err
		}
		var err error
		tok, err = s.newEmailToken(ctx, u.ID, emailtoken.PurposeResetPassword, s.Config.PasswordResetTTL)
		return err
	})
	if err != nil {
		log.Error().Err(err).Str("user_id", u.ID).Msg("forgot password token")
		return nil
	}
	// Sent to the address stored on the account, never one from the request.
	s.Email.SendPasswordReset(ctx, u, tok, s.Config.PasswordResetTTL)
	s.Audit.Record(ctx, u.ID, audit.EventPasswordResetRequest, nil)
	return nil
}

// adminTarget loads a user an admin wants to email.
func (s *AccountService) adminTarget(ctx context.Context, userID string) (*user.User, error) {
	u, err := s.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.Email == nil {
		return nil, apperr.ErrNoEmail
	}
	if u.Disabled() {
		return nil, apperr.ErrUserDisabled
	}
	return u, nil
}

func (s *AccountService) SendPasswordReset(ctx context.Context, userID string, setup bool) error {
	u, err := s.adminTarget(ctx, userID)
	if err != nil {
		return err
	}
	ttl := s.Config.PasswordResetTTL
	if setup {
		ttl = s.Config.AccountSetupTTL
	}
	var tok string
	err = s.Tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.EmailTokens.ConsumeAllForUser(ctx, u.ID, emailtoken.PurposeResetPassword, s.now()); err != nil {
			return err
		}
		var err error
		tok, err = s.newEmailToken(ctx, u.ID, emailtoken.PurposeResetPassword, ttl)
		return err
	})
	if err != nil {
		return err
	}
	if setup {
		s.Email.SendAccountSetup(ctx, u, tok, ttl)
	} else {
		s.Email.SendPasswordReset(ctx, u, tok, ttl)
	}
	return nil
}

func (s *AccountService) SendVerification(ctx context.Context, userID string) error {
	u, err := s.adminTarget(ctx, userID)
	if err != nil {
		return err
	}
	if u.EmailVerified() {
		return apperr.ErrAlreadyVerified
	}
	tok, err := s.newEmailToken(ctx, u.ID, emailtoken.PurposeVerifyEmail, s.Config.EmailVerifyTTL)
	if err != nil {
		return err
	}
	s.Email.SendVerification(ctx, u, tok, s.Config.EmailVerifyTTL)
	return nil
}

func (s *AccountService) ResetPassword(ctx context.Context, raw, newPassword string) error {
	var u *user.User
	var revoked int64
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		t, err := s.consume(ctx, raw, emailtoken.PurposeResetPassword)
		if err != nil {
			return err
		}
		if u, err = s.Users.FindByID(ctx, t.UserID); err != nil {
			return err
		}
		if u.Disabled() {
			return apperr.ErrInvalidToken
		}
		// Policy failure rolls back, so the link still works for a second try.
		if err := password.CheckPolicy(newPassword, u.Username, u.EmailOrEmpty()); err != nil {
			return apperr.New(400, "weak_password", err.Error())
		}
		hash, err := s.Hasher.Hash(newPassword)
		if err != nil {
			return err
		}
		now := s.now()
		if err := s.Credentials.Upsert(ctx, u.ID, hash); err != nil {
			return err
		}
		if err := s.EmailTokens.ConsumeAllForUser(ctx, u.ID, emailtoken.PurposeResetPassword, now); err != nil {
			return err
		}
		// The link reached the stored address, which proves ownership.
		if u.EmailVerifiedAt == nil {
			if err := s.Users.SetEmailVerified(ctx, u.ID, now); err != nil {
				return err
			}
		}
		revoked, err = s.Sessions.RevokeAll(ctx, u.ID, "")
		return err
	})
	if err != nil {
		if _, ok := apperr.As(err); ok {
			s.Metrics.PasswordReset(ctx, metrics.OutcomeRejected)
		} else {
			s.Metrics.PasswordReset(ctx, metrics.OutcomeError)
		}
		return err
	}
	s.Metrics.PasswordReset(ctx, metrics.OutcomeSuccess)
	s.Audit.Record(ctx, u.ID, audit.EventPasswordReset, map[string]any{"sessions_revoked": revoked})
	return nil
}

func (s *AccountService) ChangePassword(ctx context.Context, userID, keepSessionID, current, newPassword string) error {
	u, err := s.Users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	cred, err := s.Credentials.Get(ctx, userID)
	if errors.Is(err, repositories.ErrNotFound) {
		return apperr.ErrNoPassword
	}
	if err != nil {
		return err
	}
	if len(current) > 4*password.MaxLength {
		return ErrInvalidPassword
	}
	ok, _, err := s.Hasher.Verify(current, cred.Hash)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidPassword
	}
	if err := password.CheckPolicy(newPassword, u.Username, u.EmailOrEmpty()); err != nil {
		return apperr.New(400, "weak_password", err.Error())
	}
	hash, err := s.Hasher.Hash(newPassword)
	if err != nil {
		return err
	}
	var revoked int64
	err = s.Tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.Credentials.Upsert(ctx, userID, hash); err != nil {
			return err
		}
		revoked, err = s.Sessions.RevokeAll(ctx, userID, keepSessionID)
		return err
	})
	if err != nil {
		return err
	}
	s.Audit.Record(ctx, userID, audit.EventPasswordChanged, map[string]any{"sessions_revoked": revoked})
	return nil
}

func (s *AccountService) Get(ctx context.Context, userID string) (*user.User, error) {
	u, err := s.Users.FindByID(ctx, userID)
	if errors.Is(err, repositories.ErrNotFound) {
		return nil, apperr.ErrNotFound
	}
	return u, err
}

func (s *AccountService) UpdateProfile(ctx context.Context, userID string, displayName *string) (*user.User, error) {
	if displayName != nil {
		n, err := CleanDisplayName(*displayName)
		if err != nil {
			return nil, err
		}
		if err := s.Users.SetDisplayName(ctx, userID, n); err != nil {
			return nil, err
		}
	}
	return s.Get(ctx, userID)
}

func (s *AccountService) Cleanup(ctx context.Context) error {
	_, err := s.EmailTokens.DeleteExpiredBefore(ctx, s.now().Add(-7*24*time.Hour))
	return err
}
