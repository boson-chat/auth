// Package nsaccount is the NickServ account backend's service: it checks
// NickServ credentials through a nickserv.Backend (behind the Guard's
// rate limits and lockouts) and keeps the local user record that roles,
// profiles and friends hang off, linked to the NickServ account by name.
// It never stores a NickServ password; at most an opaque services session,
// sealed with AUTH_KEY_ENCRYPTION_KEY.
package nsaccount

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/credential"
	"github.com/boson-chat/auth/internal/db/repositories/identity"
	"github.com/boson-chat/auth/internal/db/repositories/nickservacct"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/keycrypt"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/reqmeta"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/services/nickserv"
	"github.com/boson-chat/auth/internal/services/settings"
	"github.com/boson-chat/auth/metrics"
)

// Method is the session auth_method and the login metrics' method label.
const Method = "nickserv"

// DefaultSignupMessage is shown when Boson can't register NickServ accounts.
const DefaultSignupMessage = "Accounts on this network are NickServ accounts. Register on IRC with " +
	"/msg NickServ REGISTER <password> <email>, then sign in here with that account name and password."

var (
	ErrAccountLocked = apperr.New(http.StatusTooManyRequests, "account_locked",
		"too many failed sign-ins for this account or address; try again later")
	ErrRateLimited  = apperr.New(http.StatusTooManyRequests, "rate_limited", "too many requests, try again later")
	ErrUnavailable  = apperr.New(http.StatusServiceUnavailable, "accounts_unavailable", "the network's account services can't be reached right now; try again shortly")
	ErrSuspended    = apperr.New(http.StatusForbidden, "account_suspended", "this NickServ account is suspended")
	ErrRefused      = apperr.New(http.StatusForbidden, "nickserv_refused", "NickServ refused the sign-in")
	ErrNameInvalid  = apperr.New(http.StatusConflict, "account_name_unsupported", "this NickServ account name can't be used here (it isn't a valid IRC nick)")
	ErrNameConflict = apperr.New(http.StatusConflict, "account_name_conflict",
		"a different account already uses this name here; ask an admin")
	ErrReregistered = apperr.New(http.StatusConflict, "account_reregistered",
		"this NickServ account name was registered again since it was last used here; ask an admin to release the old account")
	ErrSignupUnavailable = apperr.New(http.StatusForbidden, "registration_unavailable", DefaultSignupMessage)
	// ErrPasswordManaged: password change / reset in the NickServ backend.
	ErrPasswordManaged = apperr.New(http.StatusConflict, "password_managed_by_nickserv",
		"passwords are managed by NickServ on IRC: use /msg NickServ SET PASSWORD (or your network's reset) instead")
	ErrEmailLogin  = apperr.InvalidField("login", "must be your NickServ account name (not an email address)")
	ErrInvalidCode = apperr.New(http.StatusBadRequest, "invalid_code", "the verification code is wrong or expired")
)

// Provisioner hears about NickServ accounts as they sign in, e.g. to set
// up the account in the evrd bridge (internal/services/bridge) with its
// services login. password is the NickServ password just verified: the
// provisioner may hand it on (over the internal network) but must never
// log or store it. Errors are logged and never block the sign-in.
type Provisioner interface {
	AccountSignedIn(ctx context.Context, u *user.User, account, password string) error
}

type Deps struct {
	Backend *nickserv.Backend
	Guard   *nickserv.Guard
	Users   user.UserRepositoryImpl
	Links   nickservacct.NickServAccountRepositoryImpl
	// Credentials and Identities decide whether an existing local account
	// is unclaimed (NICKSERV_LINK_EXISTING).
	Credentials credential.CredentialRepositoryImpl
	Identities  identity.IdentityRepositoryImpl
	Tx          db.TxManagerImpl
	Settings    settings.SettingsServiceImpl
	Audit       audit.AuditServiceImpl
	Metrics     *metrics.Metrics
	Config      config.NickServConfig
	// SessionKey seals stored services sessions (AUTH_KEY_ENCRYPTION_KEY).
	SessionKey []byte
	// Provisioner is optional.
	Provisioner Provisioner
	// Federated, when set, reports federated accounts (users of another
	// Boson server): a NickServ account never adopts one.
	Federated func(ctx context.Context, userID string) (bool, error)
	Now       func() time.Time
}

// SignupInfo tells clients whether Boson sign-up works.
type SignupInfo struct {
	Available bool
	// Message explains how to get an account when sign-up isn't available.
	Message string
}

// RegisterInput is a validated sign-up.
type RegisterInput struct {
	Username, Email, Password string
}

// RegisterResult is a new NickServ account and its local record.
type RegisterResult struct {
	User *user.User
	// VerificationRequired: the services emailed a code; confirm it with
	// ConfirmRegistration (or NickServ on IRC) before signing in.
	VerificationRequired bool
	// Message is the services' reply.
	Message string
}

type NickServAccountServiceImpl interface {
	// Authenticate checks NickServ credentials and returns the linked
	// local user (created on first sign-in). method labels metrics/audit
	// ("nickserv" for the login endpoint, "internal" for the SASL bridge).
	Authenticate(ctx context.Context, login, password, method string) (*user.User, error)
	// Register registers a NickServ account (when the strategy can) and its
	// local record. Call inside the registration transaction.
	Register(ctx context.Context, in RegisterInput) (*RegisterResult, error)
	// ConfirmRegistration submits the emailed verification code. With a
	// password (needed by Atheme 7.2) the attempt counts like a sign-in
	// (rate limits, lockout).
	ConfirmRegistration(ctx context.Context, account, password, code string) error
	Signup() SignupInfo
	// EndSession ends and forgets the stored services session of userID
	// (logout). Best effort.
	EndSession(ctx context.Context, userID string)
	// Cleanup deletes stale lockout rows.
	Cleanup(ctx context.Context) error
}

type NickServAccountService struct {
	Deps
	sem chan struct{}
}

func NewNickServAccountService(d Deps) NickServAccountServiceImpl {
	if d.Now == nil {
		d.Now = time.Now
	}
	n := d.Config.MaxConcurrent
	if n < 1 {
		n = 1
	}
	return &NickServAccountService{Deps: d, sem: make(chan struct{}, n)}
}

func (s *NickServAccountService) now() time.Time { return s.Now().UTC() }

func (s *NickServAccountService) Signup() SignupInfo {
	msg := s.Config.SignupMessage
	if msg == "" {
		msg = DefaultSignupMessage
	}
	if s.Backend.Registrar != nil {
		return SignupInfo{Available: true}
	}
	return SignupInfo{Message: msg}
}

// call runs fn against the services: at most MaxConcurrent at once, each
// bounded by NICKSERV_TIMEOUT.
func (s *NickServAccountService) call(ctx context.Context, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, s.Config.Timeout)
	defer cancel()
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return nickserv.ErrUnavailable
	}
	defer func() { <-s.sem }()
	return fn(ctx)
}

func (s *NickServAccountService) Authenticate(ctx context.Context, login, password, method string) (*user.User, error) {
	login = strings.TrimSpace(login)
	if strings.Contains(login, "@") {
		return nil, ErrEmailLogin
	}
	strategy := s.Backend.Strategy
	fail := func(o, reason, userID string, err error) (*user.User, error) {
		s.Metrics.NickServCheck(ctx, strategy, o)
		if o == metrics.OutcomeInvalidCredentials {
			s.Metrics.LoginAttempt(ctx, method, o)
		}
		if reason != "" {
			s.Audit.Record(ctx, userID, audit.EventLoginFailed, map[string]any{"reason": reason, "method": method})
		}
		return nil, err
	}
	if !nickserv.ValidAccount(login) || !nickserv.ValidPassword(password) {
		return fail(metrics.OutcomeInvalidCredentials, "invalid_input", "", apperr.ErrInvalidCredentials)
	}
	folded := nick.Fold(login)
	ip := reqmeta.From(ctx).IP
	denial, err := s.Guard.Allow(ctx, folded, ip)
	if err != nil {
		return nil, err
	}
	if denial != nil {
		if denial.Locked {
			return fail(metrics.OutcomeLocked, "locked", s.linkedUserID(ctx, folded), ErrAccountLocked.WithRetryAfter(denial.RetryAfter))
		}
		s.Metrics.RateLimited(ctx, "nickserv")
		return fail(metrics.OutcomeRateLimited, "", "", ErrRateLimited.WithRetryAfter(denial.RetryAfter))
	}

	var acct *nickserv.Account
	err = s.call(ctx, func(ctx context.Context) error {
		var err error
		acct, err = s.Backend.Verifier.Verify(ctx, nickserv.Credentials{Account: login, Password: password, ClientIP: ip})
		return err
	})
	switch {
	case err == nil:
	case errors.Is(err, nickserv.ErrInvalidCredentials):
		if gerr := s.Guard.Failed(ctx, folded, ip); gerr != nil {
			logger.FromCtx(ctx).Error().Err(gerr).Msg("nickserv: recording a failed attempt")
		}
		return fail(metrics.OutcomeInvalidCredentials, "wrong_password", s.linkedUserID(ctx, folded), apperr.ErrInvalidCredentials)
	case errors.Is(err, nickserv.ErrSuspended):
		return fail(metrics.OutcomeSuspended, "suspended", s.linkedUserID(ctx, folded), ErrSuspended)
	case errors.Is(err, nickserv.ErrRefused):
		msg := strings.TrimSpace(strings.TrimPrefix(err.Error(), nickserv.ErrRefused.Error()+":"))
		e := ErrRefused
		if msg != "" && msg != err.Error() {
			e = ErrRefused.WithMessage("NickServ refused the sign-in: " + msg)
		}
		return fail(metrics.OutcomeRefused, "refused", s.linkedUserID(ctx, folded), e)
	default:
		// The error text names the server and cause, never the password.
		logger.FromCtx(ctx).Error().Err(err).Str("strategy", strategy).Msg("nickserv: verification failed")
		return fail(metrics.OutcomeUnavailable, "", "", ErrUnavailable)
	}
	if err := s.Guard.Succeeded(ctx, folded); err != nil {
		logger.FromCtx(ctx).Warn().Err(err).Msg("nickserv: resetting failed attempts")
	}
	// The services may answer with another name than was typed (Anope: a
	// grouped nick signs in to its account's display name). That is the account.
	if !nickserv.ValidAccount(acct.Name) {
		acct.Name = login
	}
	u, err := s.linkWithRetry(ctx, acct)
	if err != nil {
		s.Metrics.NickServCheck(ctx, strategy, metrics.OutcomeRejected)
		return nil, err
	}
	s.Metrics.NickServCheck(ctx, strategy, metrics.OutcomeSuccess)
	if u.Disabled() {
		s.Metrics.LoginAttempt(ctx, method, metrics.OutcomeDisabled)
		s.Audit.Record(ctx, u.ID, audit.EventLoginFailed, map[string]any{"reason": "disabled", "method": method})
		return nil, apperr.ErrAccountDisabled
	}
	if acct.Confirmed != nil && !*acct.Confirmed {
		st, err := s.Settings.Get(ctx)
		if err != nil {
			return nil, err
		}
		if st.RequireEmailVerification {
			s.Metrics.LoginAttempt(ctx, method, metrics.OutcomeUnverified)
			return nil, apperr.ErrEmailNotVerified.WithMessage("confirm your NickServ registration (the code the network emailed you) before signing in")
		}
	}
	if s.Provisioner != nil {
		if err := s.Provisioner.AccountSignedIn(ctx, u, acct.Name, password); err != nil {
			logger.FromCtx(ctx).Warn().Err(err).Str("user_id", u.ID).Msg("nickserv: provisioner")
		}
	}
	return u, nil
}

// linkedUserID is the user linked to folded, "" if none (audit only).
func (s *NickServAccountService) linkedUserID(ctx context.Context, folded string) string {
	if l, err := s.Links.FindByAccountFolded(ctx, folded); err == nil {
		return l.UserID
	}
	return ""
}

// errRetry: a concurrent first sign-in created the record first.
var errRetry = errors.New("nsaccount: retry")

func (s *NickServAccountService) linkWithRetry(ctx context.Context, acct *nickserv.Account) (*user.User, error) {
	for attempt := 0; ; attempt++ {
		var u *user.User
		err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
			var err error
			u, err = s.link(ctx, acct)
			return err
		})
		if errors.Is(err, errRetry) && attempt == 0 {
			continue
		}
		if errors.Is(err, errRetry) {
			return nil, ErrNameConflict
		}
		return u, err
	}
}

// link finds or creates the local user for acct and records the check.
func (s *NickServAccountService) link(ctx context.Context, acct *nickserv.Account) (*user.User, error) {
	now := s.now()
	folded := nick.Fold(acct.Name)
	l, err := s.Links.FindByAccountFolded(ctx, folded)
	var u *user.User
	switch {
	case err == nil:
		// RFC 1459 folds [ and {; the services may not ("[a]" and "{a}"
		// can be two accounts). Only the same name, ignoring ASCII case,
		// is the same account.
		if !strings.EqualFold(l.Account, acct.Name) {
			return nil, ErrNameConflict
		}
		if l.ServicesID != "" && acct.ID != "" && l.ServicesID != acct.ID {
			s.Audit.Record(ctx, l.UserID, audit.EventNickServReregistered, map[string]any{
				"account": acct.Name, "old_services_id": l.ServicesID, "new_services_id": acct.ID,
			})
			return nil, ErrReregistered
		}
		if u, err = s.Users.FindByID(ctx, l.UserID); err != nil {
			return nil, err
		}
	case errors.Is(err, repositories.ErrNotFound):
		if u, err = s.adoptOrCreate(ctx, acct, folded, now); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	enc, exp, err := s.sealSession(u.ID, acct.Session)
	if err != nil {
		return nil, err
	}
	if err := s.Links.Touch(ctx, u.ID, acct.Name, acct.ID, s.Backend.Strategy, enc, exp, now); err != nil {
		return nil, err
	}
	if err := s.syncEmail(ctx, u, acct, now); err != nil {
		return nil, err
	}
	return u, nil
}

// adoptOrCreate links an existing local user of that name (NICKSERV_LINK_EXISTING)
// or creates one.
func (s *NickServAccountService) adoptOrCreate(ctx context.Context, acct *nickserv.Account, folded string, now time.Time) (*user.User, error) {
	existing := false
	u, err := s.Users.FindByUsernameFolded(ctx, folded)
	switch {
	case err == nil:
		ok, err := s.mayAdopt(ctx, u, acct.Name)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrNameConflict
		}
		existing = true
	case errors.Is(err, repositories.ErrNotFound):
		if err := nick.Validate(acct.Name); err != nil {
			return nil, ErrNameInvalid
		}
		u = &user.User{
			ID: ids.New(ids.User), Username: acct.Name, UsernameFolded: folded,
			Role: user.RoleUser, CreatedAt: now, UpdatedAt: now,
		}
		if err := s.Users.Create(ctx, u); err != nil {
			if errors.Is(err, user.ErrUsernameTaken) {
				return nil, errRetry
			}
			return nil, err
		}
	default:
		return nil, err
	}
	err = s.Links.Create(ctx, &nickservacct.Link{
		UserID: u.ID, Account: acct.Name, AccountFolded: folded, ServicesID: acct.ID,
		Strategy: s.Backend.Strategy, CreatedAt: now, LastVerifiedAt: now,
	})
	if errors.Is(err, nickservacct.ErrAccountLinked) {
		return nil, errRetry
	}
	if err != nil {
		return nil, err
	}
	s.Audit.Record(ctx, u.ID, audit.EventNickServLinked, map[string]any{"account": acct.Name, "existing": existing})
	return u, nil
}

// mayAdopt applies NICKSERV_LINK_EXISTING to a local user of the same name.
func (s *NickServAccountService) mayAdopt(ctx context.Context, u *user.User, account string) (bool, error) {
	if !strings.EqualFold(u.Username, account) {
		return false, nil // RFC 1459 fold only ([a] vs {a})
	}
	if s.Federated != nil {
		if fed, err := s.Federated(ctx, u.ID); err != nil || fed {
			return false, err
		}
	}
	switch s.Config.LinkExisting {
	case config.LinkExistingAll:
		return true, nil
	case config.LinkExistingUnclaimed:
		// Only an account nobody can sign in to yet: no password, no SSO.
		if _, err := s.Credentials.Get(ctx, u.ID); err == nil {
			return false, nil
		} else if !errors.Is(err, repositories.ErrNotFound) {
			return false, err
		}
		idents, err := s.Identities.ListIdentitiesByUser(ctx, u.ID)
		if err != nil {
			return false, err
		}
		return len(idents) == 0, nil
	}
	return false, nil
}

// syncEmail copies the services' email (and its confirmation) onto the
// local user. A taken address is left alone.
func (s *NickServAccountService) syncEmail(ctx context.Context, u *user.User, acct *nickserv.Account, now time.Time) error {
	addr := strings.TrimSpace(acct.Email)
	if addr == "" || len(addr) > 254 || !strings.Contains(addr, "@") {
		return nil
	}
	confirmed := acct.Confirmed != nil && *acct.Confirmed
	same := u.Email != nil && strings.EqualFold(*u.Email, addr)
	if same && (u.EmailVerified() || !confirmed) {
		return nil
	}
	var verified *time.Time
	if confirmed {
		verified = &now
	} else if same {
		verified = u.EmailVerifiedAt
	}
	err := s.Users.SetEmail(ctx, u.ID, &addr, verified)
	if errors.Is(err, user.ErrEmailTaken) {
		logger.FromCtx(ctx).Info().Str("user_id", u.ID).Msg("nickserv: the account's email belongs to another local account; not copied")
		return nil
	}
	if err == nil {
		u.Email, u.EmailVerifiedAt = &addr, verified
	}
	return err
}

func sessionAAD(userID string) []byte { return []byte("nickserv_session:" + userID) }

func (s *NickServAccountService) sealSession(userID string, sess *nickserv.Session) ([]byte, *time.Time, error) {
	if sess == nil || sess.Token == "" || !s.Config.StoreSession {
		return nil, nil, nil
	}
	enc, err := keycrypt.Seal(s.SessionKey, []byte(sess.Token), sessionAAD(userID))
	if err != nil {
		return nil, nil, err
	}
	exp := sess.ExpiresAt.UTC()
	return enc, &exp, nil
}

func (s *NickServAccountService) EndSession(ctx context.Context, userID string) {
	l, err := s.Links.FindByUserID(ctx, userID)
	if err != nil || l.SessionEnc == nil {
		return
	}
	log := logger.FromCtx(ctx)
	if s.Backend.Sessions != nil && l.SessionExpiresAt != nil && l.SessionExpiresAt.After(s.now()) {
		tok, err := keycrypt.Open(s.SessionKey, l.SessionEnc, sessionAAD(userID))
		if err == nil {
			err = s.call(ctx, func(ctx context.Context) error {
				return s.Backend.Sessions.EndSession(ctx, l.Account, nickserv.Session{Token: string(tok)})
			})
		}
		if err != nil {
			log.Warn().Err(err).Str("user_id", userID).Msg("nickserv: ending the services session")
		}
	}
	if err := s.Links.ClearSession(ctx, userID); err != nil {
		log.Warn().Err(err).Str("user_id", userID).Msg("nickserv: clearing the services session")
	}
}

func (s *NickServAccountService) Register(ctx context.Context, in RegisterInput) (*RegisterResult, error) {
	if s.Backend.Registrar == nil {
		return nil, ErrSignupUnavailable.WithMessage(s.Signup().Message)
	}
	if !nickserv.ValidAccount(in.Username) {
		return nil, apperr.New(http.StatusBadRequest, "invalid_username", "username can't be used as a NickServ account name")
	}
	if !nickserv.ValidPassword(in.Password) {
		return nil, apperr.New(http.StatusBadRequest, "weak_password", "password must be 1-512 characters without line breaks")
	}
	folded := nick.Fold(in.Username)
	// A local account (e.g. made by an admin) may already hold the name.
	if _, err := s.Users.FindByUsernameFolded(ctx, folded); err == nil {
		return nil, apperr.ErrUsernameTaken
	} else if !errors.Is(err, repositories.ErrNotFound) {
		return nil, err
	}
	var reg *nickserv.Registration
	err := s.call(ctx, func(ctx context.Context) error {
		var err error
		reg, err = s.Backend.Registrar.Register(ctx, in.Username, in.Password, in.Email, reqmeta.From(ctx).IP)
		return err
	})
	var rej *nickserv.RejectedError
	switch {
	case err == nil:
	case errors.Is(err, nickserv.ErrAccountExists):
		return nil, apperr.ErrUsernameTaken
	case errors.As(err, &rej):
		return nil, apperr.New(http.StatusBadRequest, "registration_rejected", "NickServ: "+rej.Message)
	default:
		logger.FromCtx(ctx).Error().Err(err).Msg("nickserv: registration failed")
		return nil, ErrUnavailable
	}
	now := s.now()
	addr := in.Email
	u := &user.User{
		ID: ids.New(ids.User), Username: in.Username, UsernameFolded: folded, Email: &addr,
		Role: user.RoleUser, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.Users.Create(ctx, u); err != nil {
		if errors.Is(err, user.ErrEmailTaken) {
			// The NickServ account exists now; link it without the email.
			u.Email = nil
			err = s.Users.Create(ctx, u)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := s.Links.Create(ctx, &nickservacct.Link{
		UserID: u.ID, Account: in.Username, AccountFolded: folded, Strategy: s.Backend.Strategy,
		CreatedAt: now, LastVerifiedAt: now,
	}); err != nil {
		return nil, err
	}
	s.Audit.Record(ctx, u.ID, audit.EventNickServLinked, map[string]any{"account": in.Username, "existing": false, "registered": true})
	return &RegisterResult{User: u, VerificationRequired: reg.VerificationRequired, Message: reg.Message}, nil
}

func (s *NickServAccountService) ConfirmRegistration(ctx context.Context, account, password, code string) error {
	account, code = strings.TrimSpace(account), strings.TrimSpace(code)
	if s.Backend.Registrar == nil {
		return ErrSignupUnavailable.WithMessage(s.Signup().Message)
	}
	if !nickserv.ValidAccount(account) || code == "" || len(code) > 128 || strings.ContainsAny(code, " \r\n\x00") {
		return ErrInvalidCode
	}
	if password != "" && !nickserv.ValidPassword(password) {
		return apperr.ErrInvalidCredentials
	}
	folded, ip := nick.Fold(account), reqmeta.From(ctx).IP
	if password != "" {
		denial, err := s.Guard.Allow(ctx, folded, ip)
		if err != nil {
			return err
		}
		if denial != nil && denial.Locked {
			return ErrAccountLocked.WithRetryAfter(denial.RetryAfter)
		} else if denial != nil {
			return ErrRateLimited.WithRetryAfter(denial.RetryAfter)
		}
	}
	err := s.call(ctx, func(ctx context.Context) error {
		return s.Backend.Registrar.ConfirmRegistration(ctx, account, password, code, ip)
	})
	var rej *nickserv.RejectedError
	switch {
	case errors.Is(err, nickserv.ErrInvalidCredentials):
		if gerr := s.Guard.Failed(ctx, folded, ip); gerr != nil {
			logger.FromCtx(ctx).Error().Err(gerr).Msg("nickserv: recording a failed attempt")
		}
		return apperr.ErrInvalidCredentials
	case errors.Is(err, nickserv.ErrSuspended):
		return ErrSuspended
	case err == nil:
	case errors.Is(err, nickserv.ErrInvalidCode):
		return ErrInvalidCode
	case errors.As(err, &rej):
		return apperr.New(http.StatusBadRequest, "invalid_code", "NickServ: "+rej.Message)
	default:
		logger.FromCtx(ctx).Error().Err(err).Msg("nickserv: registration verification failed")
		return ErrUnavailable
	}
	// The emailed code proves the address: mark it verified locally.
	if l, err := s.Links.FindByAccountFolded(ctx, nick.Fold(account)); err == nil {
		if u, err := s.Users.FindByID(ctx, l.UserID); err == nil && u.Email != nil && !u.EmailVerified() {
			if err := s.Users.SetEmailVerified(ctx, u.ID, s.now()); err != nil {
				return err
			}
			s.Audit.Record(ctx, u.ID, audit.EventEmailVerified, map[string]any{"via": Method})
		}
	}
	return nil
}

func (s *NickServAccountService) Cleanup(ctx context.Context) error {
	_, err := s.Links.DeleteLockoutsBefore(ctx, s.now().Add(-(s.Config.LockoutWindow + s.Config.LockoutDuration + time.Hour)))
	return err
}
