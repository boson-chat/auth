// Package federation is Boson federated login (docs/federation.md).
//
// Home side: Assert issues a short-lived assertion (typ boson-fed+jwt)
// about the caller for another Boson server, signed with the usual
// signing keys. Remote side: Login verifies one (discovery through the
// home's boson.json, its JWKS, replay cache, trust policy), keeps a local
// federated account keyed by (iss, sub) and signs it in like any local
// account. The rest is the remote admin controls: remote users, bans,
// blocked domains and the runtime settings.
package federation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	fedrepo "github.com/boson-chat/auth/internal/db/repositories/federation"
	"github.com/boson-chat/auth/internal/db/repositories/role"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/services/account"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/services/authn"
	"github.com/boson-chat/auth/internal/services/roles"
	"github.com/boson-chat/auth/internal/services/session"
	"github.com/boson-chat/auth/internal/services/token"
	"github.com/boson-chat/auth/internal/textutil"
	"github.com/boson-chat/auth/metrics"
	"github.com/golang-jwt/jwt/v5"
)

// Method is the session auth_method (and metrics method) of federated sign-ins.
const Method = "federation"

// clockSkew is allowed on exp / iat.
const clockSkew = 60 * time.Second

// Client-facing errors (spec §3).
var (
	ErrFederationOff  = apperr.New(http.StatusForbidden, "federation_off", "this server doesn't accept accounts from other servers")
	ErrNotTrusted     = apperr.New(http.StatusForbidden, "domain_not_trusted", "this server doesn't accept accounts from that server")
	ErrDomainBlocked  = apperr.New(http.StatusForbidden, "domain_blocked", "accounts from that server are blocked here")
	ErrIdentityBanned = apperr.New(http.StatusForbidden, "identity_banned", "this account is banned here")
	ErrDiscovery      = apperr.New(http.StatusBadGateway, "discovery_failed", "couldn't verify the home server")
	ErrBadAssertion   = apperr.New(http.StatusUnauthorized, "bad_assertion", "the sign-in assertion is invalid or expired")
	ErrReplayed       = apperr.New(http.StatusUnauthorized, "replayed", "the sign-in assertion was already used")
	// ErrFederatedAccount: a federated account asked for an assertion
	// (accounts only federate from their own home).
	ErrFederatedAccount = apperr.New(http.StatusForbidden, "federated_account", "accounts from other servers can't sign in elsewhere from here")
	errNotFederated     = apperr.New(http.StatusNotFound, "not_found", "no such remote user")
)

// Metadata is the federation section of this install's boson.json
// (GET /.well-known/boson-federation.json).
type Metadata struct {
	Version           int    `json:"version"`
	Issuer            string `json:"issuer"`
	JWKSURI           string `json:"jwks_uri"`
	AssertionEndpoint string `json:"assertion_endpoint"`
	LoginEndpoint     string `json:"login_endpoint"`
	Accepts           string `json:"accepts"`
}

// LoginResult is a successful federated sign-in.
type LoginResult struct {
	Tokens   *authn.Tokens
	Account  *fedrepo.Account
	Created  bool
	Identity string
}

// FederationServiceImpl is what the HTTP layer uses.
type FederationServiceImpl interface {
	Settings(ctx context.Context) (Settings, error)
	UpdateSettings(ctx context.Context, actorID string, p Patch) (Settings, error)
	Metadata(ctx context.Context) (Metadata, error)
	IsFederated(ctx context.Context, userID string) (bool, error)
	RemoteVoice(ctx context.Context) (bool, error)
	Account(ctx context.Context, userID string) (*fedrepo.Account, error)
	Assert(ctx context.Context, p *authn.Principal, audience string) (string, time.Time, error)
	Login(ctx context.Context, assertion string) (*LoginResult, error)
	AdminSettings(ctx context.Context) (Settings, error)
	Identities(ctx context.Context, handles []string) (map[string]*Identity, error)
	SetFile(cfg *config.FederationConfig, fields []string)
	ListUsers(ctx context.Context, f fedrepo.ListFilter, cursor string) ([]*fedrepo.AccountView, int64, string, error)
	GetUser(ctx context.Context, userID string) (*fedrepo.AccountView, error)
	Ban(ctx context.Context, actorID, userID, reason string) (*fedrepo.AccountView, error)
	Unban(ctx context.Context, actorID, userID string) (*fedrepo.AccountView, error)
	ListBans(ctx context.Context) ([]*fedrepo.Ban, error)
	RevokeDomainSessions(ctx context.Context, actorID, domain string) (string, int64, error)
	Cleanup(ctx context.Context) error
}

var _ FederationServiceImpl = (*FederationService)(nil)

// Deps are the service's collaborators.
type Deps struct {
	Repo     fedrepo.FederationRepositoryImpl
	Users    user.UserRepositoryImpl
	Roles    role.RoleRepositoryImpl
	Tx       db.TxManagerImpl
	Sessions session.SessionServiceImpl
	Tokens   token.TokenServiceImpl
	Audit    audit.AuditServiceImpl
	Metrics  *metrics.Metrics
	Config   config.Config
	// HTTPClient fetches discovery, JWKS and directory listings (nil:
	// NewHTTPClient).
	HTTPClient *http.Client
	// FilesClient talks to the files service's internal API (nil: http.DefaultClient).
	FilesClient *http.Client
	Now         func() time.Time
}

// FederationService implements the federation flows. Authn must be set
// before Login is used (authn depends on the service too).
type FederationService struct {
	Deps
	Authn    authn.AuthnServiceImpl
	settings *settingsStore
	remote   *remote
	files    *filesQuota
}

func NewFederationService(d Deps) *FederationService {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.HTTPClient == nil {
		f := d.Config.FederationConfig
		d.HTTPClient = NewHTTPClient(f.Timeout(), f.AllowHTTP)
	}
	if d.Metrics == nil {
		d.Metrics = metrics.Noop()
	}
	s := &FederationService{Deps: d}
	s.settings = newSettingsStore(d.Repo, d.Tx, d.Audit, d.Config, d.Now)
	s.remote = newRemote(d.HTTPClient, d.Config.FederationConfig.AllowHTTP, d.Now)
	s.files = newFilesQuota(d.Config.FilesInternalConfig, d.FilesClient)
	return s
}

func (s *FederationService) now() time.Time { return s.Now().UTC() }

func (s *FederationService) issuer() string { return s.Config.TokenConfig.Issuer }

// ---- settings and metadata ------------------------------------------------

// Settings returns the effective settings.
func (s *FederationService) Settings(ctx context.Context) (Settings, error) {
	return s.settings.get(ctx)
}

// AdminSettings is GET /v1/admin/federation: the settings plus the
// number of remote users.
func (s *FederationService) AdminSettings(ctx context.Context) (Settings, error) {
	st, err := s.Settings(ctx)
	if err != nil {
		return st, err
	}
	st.RemoteUsers, err = s.Repo.Count(ctx)
	return st, err
}

// UpdateSettings applies an admin patch (409 settings_managed in file
// mode). A domain added to block is refused from the next sign-in; its
// users' sessions end with RevokeDomainSessions.
func (s *FederationService) UpdateSettings(ctx context.Context, actorID string, p Patch) (Settings, error) {
	if _, err := s.settings.update(ctx, actorID, p); err != nil {
		return Settings{}, err
	}
	return s.AdminSettings(ctx)
}

// SetFile switches the settings to the stack config file's values (env
// with auth.federation applied; fields = the keys the file sets), or back
// to the database with nil.
func (s *FederationService) SetFile(cfg *config.FederationConfig, fields []string) {
	s.settings.setFile(cfg, fields)
}

// Metadata is what the stack publishes as boson.json's federation section.
func (s *FederationService) Metadata(ctx context.Context) (Metadata, error) {
	st, err := s.Settings(ctx)
	if err != nil {
		return Metadata{}, err
	}
	base := s.Config.HTTPConfig.PublicURL
	return Metadata{
		Version: 1, Issuer: s.issuer(), JWKSURI: base + "/.well-known/jwks.json",
		AssertionEndpoint: base + "/v1/federation/assertions", LoginEndpoint: base + "/v1/federation/login",
		Accepts: st.Mode,
	}, nil
}

// IsFederated reports whether userID is a federated account.
func (s *FederationService) IsFederated(ctx context.Context, userID string) (bool, error) {
	return s.Repo.IsFederated(ctx, userID)
}

// RemoteVoice reports whether federated users may get voice tokens.
func (s *FederationService) RemoteVoice(ctx context.Context) (bool, error) {
	st, err := s.Settings(ctx)
	return st.RemoteVoice, err
}

// Account returns userID's federated account, or nil when it is local.
func (s *FederationService) Account(ctx context.Context, userID string) (*fedrepo.Account, error) {
	a, err := s.Repo.FindByUserID(ctx, userID)
	if errors.Is(err, repositories.ErrNotFound) {
		return nil, nil
	}
	return a, err
}

// ---- home side ------------------------------------------------------------

// Assert issues an assertion about the caller for audience (the remote's
// issuer URL). Refused while federation is off, for disabled accounts and
// for federated accounts.
func (s *FederationService) Assert(ctx context.Context, p *authn.Principal, audience string) (string, time.Time, error) {
	st, err := s.Settings(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	if st.Mode == config.FederationOff {
		return "", time.Time{}, ErrFederationOff
	}
	if p == nil || p.User == nil {
		return "", time.Time{}, apperr.ErrUnauthenticated
	}
	if p.User.Disabled() {
		return "", time.Time{}, apperr.ErrAccountDisabled
	}
	if fed, err := s.IsFederated(ctx, p.UserID); err != nil {
		return "", time.Time{}, err
	} else if fed {
		return "", time.Time{}, ErrFederatedAccount
	}
	audience = strings.TrimSpace(audience)
	if len(audience) > 512 || config.ValidateServiceURL(audience, s.Config.FederationConfig.AllowHTTP) != nil {
		return "", time.Time{}, apperr.InvalidField("audience", "must be the other server's issuer URL, e.g. https://auth.example.org")
	}
	if audience == s.issuer() {
		return "", time.Time{}, apperr.InvalidField("audience", "is this server")
	}
	if st.Domain == "" {
		return "", time.Time{}, errors.New("federation: FEDERATION_DOMAIN is not set and can't be derived from ISSUER")
	}
	tok, exp, err := s.Tokens.MintFederation(ctx, token.FederationAssertion{
		User: p.User, Audience: audience, Domain: st.Domain, TTL: config.FederationAssertionTTL,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	logger.FromCtx(ctx).Info().Str("user_id", p.UserID).Str("audience", audience).Msg("federation assertion issued")
	s.Audit.Record(ctx, p.UserID, audit.EventFederationAssertion, map[string]any{"audience": audience, "session_id": p.SessionID})
	return tok, exp, nil
}

// ---- remote side ----------------------------------------------------------

type assertionClaims struct {
	BosonDomain       string `json:"boson_domain"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Picture           string `json:"picture"`
	EmailVerified     bool   `json:"email_verified"`
	jwt.RegisteredClaims
}

func (s *FederationService) refuse(ctx context.Context, err error, reason, domain string) error {
	outcome := metrics.OutcomeRejected
	if errors.Is(err, ErrBadAssertion) || errors.Is(err, ErrReplayed) {
		outcome = metrics.OutcomeInvalid
	}
	s.Metrics.LoginAttempt(ctx, Method, outcome)
	s.Audit.Record(ctx, "", audit.EventFederationLoginFailed, map[string]any{"reason": reason, "domain": domain})
	return err
}

// Login signs in the user an assertion vouches for (spec §3).
func (s *FederationService) Login(ctx context.Context, raw string) (*LoginResult, error) {
	st, err := s.Settings(ctx)
	if err != nil {
		return nil, err
	}
	if st.Mode == config.FederationOff {
		return nil, s.refuse(ctx, ErrFederationOff, "federation_off", "")
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 8192 {
		return nil, s.refuse(ctx, ErrBadAssertion, "malformed", "")
	}

	// 1. Read iss and boson_domain without trusting them yet.
	var peek assertionClaims
	unverified, _, err := jwt.NewParser().ParseUnverified(raw, &peek)
	if err != nil {
		return nil, s.refuse(ctx, ErrBadAssertion, "malformed", "")
	}
	if typ, _ := unverified.Header["typ"].(string); typ != token.TypFederation {
		return nil, s.refuse(ctx, ErrBadAssertion, "wrong_typ", "")
	}
	domain := strings.ToLower(peek.BosonDomain)
	iss := peek.Issuer
	if !config.ValidDomain(domain) || config.ValidateServiceURL(iss, s.Config.FederationConfig.AllowHTTP) != nil {
		return nil, s.refuse(ctx, ErrBadAssertion, "bad_issuer_or_domain", domain)
	}
	if iss == s.issuer() {
		return nil, s.refuse(ctx, ErrBadAssertion, "own_issuer", domain)
	}

	// Policy checks that need no network first.
	if config.DomainListMatches(st.Block, domain) {
		return nil, s.refuse(ctx, ErrDomainBlocked, "domain_blocked", domain)
	}
	if st.Mode == config.FederationAllowlist && !config.DomainListMatches(st.Allow, domain) {
		return nil, s.refuse(ctx, ErrNotTrusted, "not_allowlisted", domain)
	}

	// 2. Discovery: the domain's boson.json must name this issuer.
	disc, err := s.remote.discovery(ctx, domain)
	if err != nil {
		logger.FromCtx(ctx).Warn().Err(err).Str("domain", domain).Msg("federation discovery failed")
		return nil, s.refuse(ctx, ErrDiscovery, "discovery_failed", domain)
	}
	if disc.Issuer != iss {
		return nil, s.refuse(ctx, ErrBadAssertion, "issuer_mismatch", domain)
	}
	if disc.Accepts == config.FederationOff {
		return nil, s.refuse(ctx, ErrDiscovery.WithMessage("the home server has federation turned off"), "home_federation_off", domain)
	}

	// 3. Signature and claims.
	var keyErr error
	var c assertionClaims
	_, err = jwt.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		k, err := s.remote.key(ctx, disc.JWKSURI, kid)
		if err != nil && !errors.Is(err, errUnknownKey) {
			keyErr = err
		}
		return k, err
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(iss),
		jwt.WithAudience(s.issuer()),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(clockSkew),
		jwt.WithTimeFunc(s.Now),
	)
	if keyErr != nil {
		logger.FromCtx(ctx).Warn().Err(keyErr).Str("domain", domain).Msg("federation JWKS fetch failed")
		return nil, s.refuse(ctx, ErrDiscovery, "jwks_failed", domain)
	}
	if err != nil {
		reason := "invalid"
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			reason = "expired"
		case errors.Is(err, jwt.ErrTokenInvalidAudience):
			reason = "wrong_audience"
		case errors.Is(err, jwt.ErrTokenSignatureInvalid), errors.Is(err, jwt.ErrTokenUnverifiable):
			reason = "bad_signature"
		}
		return nil, s.refuse(ctx, ErrBadAssertion, reason, domain)
	}
	now := s.now()
	if c.IssuedAt == nil || c.ExpiresAt == nil || c.ExpiresAt.Sub(c.IssuedAt.Time) > config.FederationAssertionTTL ||
		c.ExpiresAt.After(now.Add(config.FederationAssertionTTL+clockSkew)) {
		return nil, s.refuse(ctx, ErrBadAssertion, "lifetime", domain)
	}
	if c.Subject == "" || len(c.Subject) > 256 || !textutil.Storable(c.Subject) || c.ID == "" || len(c.ID) > 256 ||
		strings.ToLower(c.BosonDomain) != domain {
		return nil, s.refuse(ctx, ErrBadAssertion, "missing_claims", domain)
	}
	homeUser := strings.TrimSpace(c.PreferredUsername)
	if homeUser == "" || len(homeUser) > 64 || !textutil.Storable(homeUser) || strings.ContainsAny(homeUser, "@ \t") {
		return nil, s.refuse(ctx, ErrBadAssertion, "bad_username", domain)
	}

	// Replay: every jti once, until it expires.
	sum := sha256.Sum256([]byte(iss + " " + c.ID))
	fresh, err := s.Repo.MarkSeen(ctx, hex.EncodeToString(sum[:]), c.ExpiresAt.Add(clockSkew))
	if err != nil {
		return nil, err
	}
	if !fresh {
		return nil, s.refuse(ctx, ErrReplayed, "replayed", domain)
	}

	// 4. Trust policy needing the network: the directory.
	if st.Mode == config.FederationDirectory {
		hosts := []string{domain}
		if h := disc.IRCHost; h != "" && h != domain && strings.HasSuffix(h, "."+domain) {
			hosts = append(hosts, h)
		}
		ok, err := s.remote.listed(ctx, st.DirectoryURL, hosts)
		if err != nil && !ok {
			logger.FromCtx(ctx).Warn().Err(err).Str("domain", domain).Msg("federation directory lookup failed")
			return nil, s.refuse(ctx, ErrDiscovery.WithMessage("couldn't check the directory"), "directory_failed", domain)
		}
		if !ok {
			return nil, s.refuse(ctx, ErrNotTrusted.WithMessage("this server only accepts accounts from verified servers"), "not_in_directory", domain)
		}
	}
	if banned, err := s.Repo.IsBanned(ctx, iss, c.Subject); err != nil {
		return nil, err
	} else if banned {
		return nil, s.refuse(ctx, ErrIdentityBanned, "identity_banned", domain)
	}

	// 5. The local account.
	prof := profile{
		issuer: iss, subject: c.Subject, domain: domain, username: homeUser,
		name: cleanName(c.Name), picture: cleanPicture(c.Picture), emailVerified: c.EmailVerified,
	}
	u, acct, created, err := s.upsert(ctx, st, prof)
	if err != nil {
		return nil, err
	}

	// 6. A session like any other.
	toks, err := s.Authn.IssueSession(ctx, u, Method)
	if err != nil {
		return nil, err
	}
	s.applyQuota(ctx, st, acct)
	s.Audit.Record(ctx, u.ID, audit.EventFederationLogin, map[string]any{
		"identity": acct.Identity(), "domain": domain, "created": created, "session_id": toks.Session.ID,
	})
	return &LoginResult{Tokens: toks, Account: acct, Created: created, Identity: acct.Identity()}, nil
}

type profile struct {
	issuer, subject, domain, username, name, picture string
	emailVerified                                    bool
}

func cleanName(n string) string {
	n = strings.TrimSpace(n)
	if utf8.RuneCountInString(n) > 64 {
		n = string([]rune(n)[:64])
	}
	out, err := account.CleanDisplayName(n)
	if err != nil {
		return ""
	}
	return out
}

func cleanPicture(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || len(p) > 2048 {
		return ""
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return ""
	}
	return p
}

func ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// upsert finds or creates the federated account for prof and refreshes
// its profile.
func (s *FederationService) upsert(ctx context.Context, st Settings, prof profile) (*user.User, *fedrepo.Account, bool, error) {
	var (
		u       *user.User
		acct    *fedrepo.Account
		created bool
		err     error
	)
	for attempt := range 4 {
		created = false
		err = s.Tx.WithTx(ctx, func(ctx context.Context) error {
			now := s.now()
			a, err := s.Repo.FindByIdentity(ctx, prof.issuer, prof.subject)
			if err == nil {
				if u, err = s.Users.FindByID(ctx, a.UserID); err != nil {
					return err
				}
				if err := s.Repo.Touch(ctx, a.UserID, prof.username, ptr(prof.picture), prof.emailVerified, now); err != nil {
					return err
				}
				if prof.name != "" && prof.name != u.DisplayName {
					if err := s.Users.SetDisplayName(ctx, u.ID, prof.name); err != nil {
						return err
					}
					u.DisplayName = prof.name
				}
				a.HomeUsername, a.Picture, a.EmailVerified, a.LastLoginAt = prof.username, ptr(prof.picture), prof.emailVerified, now
				acct = a
				return nil
			}
			if !errors.Is(err, repositories.ErrNotFound) {
				return err
			}
			handle, err := s.pickHandle(ctx, prof, attempt)
			if err != nil {
				return err
			}
			nu := &user.User{
				ID: ids.New(ids.User), Username: handle, UsernameFolded: nick.Fold(handle),
				DisplayName: prof.name, Role: user.RoleUser, CreatedAt: now, UpdatedAt: now,
			}
			if err := s.Users.Create(ctx, nu); err != nil {
				return err
			}
			a = &fedrepo.Account{
				UserID: nu.ID, Issuer: prof.issuer, Subject: prof.subject, HomeDomain: prof.domain,
				HomeUsername: prof.username, Picture: ptr(prof.picture), EmailVerified: prof.emailVerified,
				CreatedAt: now, LastLoginAt: now,
			}
			if err := s.Repo.Create(ctx, a); err != nil {
				return err
			}
			if err := s.assignRemoteRole(ctx, st, nu.ID, now); err != nil {
				return err
			}
			u, acct, created = nu, a, true
			return nil
		})
		if errors.Is(err, user.ErrUsernameTaken) || errors.Is(err, fedrepo.ErrIdentityTaken) {
			continue
		}
		break
	}
	if err != nil {
		return nil, nil, false, err
	}
	if created {
		s.Metrics.Registration(ctx, metrics.OutcomeSuccess)
		s.Audit.Record(ctx, u.ID, audit.EventRegister, map[string]any{
			"method": Method, "identity": acct.Identity(), "issuer": acct.Issuer, "handle": u.Username,
		})
	}
	return u, acct, created, nil
}

// pickHandle chooses a free local handle (spec §3.5): the home username,
// then with the domain label, then numbered; random as a last resort.
func (s *FederationService) pickHandle(ctx context.Context, prof profile, attempt int) (string, error) {
	free := func(h string) (bool, error) {
		_, err := s.Users.FindByUsernameFolded(ctx, nick.Fold(h))
		if errors.Is(err, repositories.ErrNotFound) {
			return true, nil
		}
		return false, err
	}
	if attempt == 0 {
		for _, h := range handleCandidates(prof.username, prof.domain) {
			if ok, err := free(h); err != nil || ok {
				return h, err
			}
		}
	}
	for range 10 {
		h, err := randomHandle(prof.username)
		if err != nil {
			return "", err
		}
		if ok, err := free(h); err != nil || ok {
			return h, err
		}
	}
	return "", errors.New("federation: no free handle")
}

// assignRemoteRole gives a new federated account the remote role
// (FEDERATION_REMOTE_ROLE), creating the role when it doesn't exist.
func (s *FederationService) assignRemoteRole(ctx context.Context, st Settings, userID string, now time.Time) error {
	if st.RemoteRole == "" {
		return nil
	}
	name, err := roles.NormalizeName(st.RemoteRole)
	if err != nil {
		return fmt.Errorf("FEDERATION_REMOTE_ROLE: %w", err)
	}
	slug := roles.Slug(name)
	find := func() (string, error) {
		all, err := s.Roles.List(ctx)
		if err != nil {
			return "", err
		}
		for _, r := range all {
			if r.Slug == slug || strings.EqualFold(r.Name, name) || r.ID == st.RemoteRole {
				if r.Is(role.BuiltinMember) {
					return "", nil // implicit
				}
				return r.ID, nil
			}
		}
		return "", repositories.ErrNotFound
	}
	id, err := find()
	if errors.Is(err, repositories.ErrNotFound) {
		if err := s.Roles.Lock(ctx); err != nil {
			return err
		}
		if id, err = find(); errors.Is(err, repositories.ErrNotFound) {
			r := &role.Role{ID: ids.New(ids.Role), Name: name, Slug: slug, Position: roles.MinPosition,
				Permissions: repositories.StringList{}, CreatedAt: now, UpdatedAt: now}
			if err := s.Roles.Create(ctx, r); err != nil {
				return err
			}
			s.Audit.Record(ctx, "", audit.EventRoleCreated, map[string]any{"role_id": r.ID, "name": name, "reason": "federation_remote_role"})
			id, err = r.ID, nil
		}
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if id == "" {
		return nil
	}
	return s.Roles.AddUserRoles(ctx, userID, []string{id}, nil, now)
}

// applyQuota pushes the remote upload limits to the files service when
// they changed since the last push for this account (best effort).
func (s *FederationService) applyQuota(ctx context.Context, st Settings, a *fedrepo.Account) {
	if !s.files.enabled() {
		return
	}
	maxFile, _ := config.ParseSize(s.Config.FederationConfig.RemoteMaxFile)
	want := quotaKey(st.remoteUploadBytes, maxFile)
	if a.QuotaApplied != nil && *a.QuotaApplied == want {
		return
	}
	if a.QuotaApplied == nil && want == "" {
		return // never overridden, nothing to remove
	}
	if err := s.files.apply(ctx, a.UserID, st.remoteUploadBytes, maxFile); err != nil {
		logger.FromCtx(ctx).Warn().Err(err).Str("user_id", a.UserID).Msg("federation: setting the files quota failed")
		return
	}
	if err := s.Repo.SetQuotaApplied(ctx, a.UserID, want); err != nil {
		logger.FromCtx(ctx).Warn().Err(err).Str("user_id", a.UserID).Msg("federation: recording the files quota failed")
		return
	}
	a.QuotaApplied = &want
}

// Identity is the public answer to "who is this handle?".
type Identity struct {
	Handle     string  `json:"handle"`
	Federated  bool    `json:"federated"`
	Identity   *string `json:"identity"`
	HomeDomain *string `json:"home_domain"`
}

// MaxIdentityLookup bounds POST /v1/users/identities.
const MaxIdentityLookup = 200

// Identities says, for each handle (as given), whether it is a federated
// account here and whose. Local and unknown handles look the same
// (federated: false).
func (s *FederationService) Identities(ctx context.Context, handles []string) (map[string]*Identity, error) {
	if len(handles) > MaxIdentityLookup {
		return nil, apperr.InvalidField("handles", fmt.Sprintf("may have at most %d entries", MaxIdentityLookup))
	}
	out := make(map[string]*Identity, len(handles))
	folded := make([]string, 0, len(handles))
	for _, h := range handles {
		if _, ok := out[h]; ok {
			continue
		}
		out[h] = &Identity{Handle: h}
		if len(h) <= nick.MaxLen && textutil.Storable(h) && h != "" {
			folded = append(folded, nick.Fold(h))
		}
	}
	found, err := s.Repo.ByUsernames(ctx, folded)
	if err != nil {
		return nil, err
	}
	for h, id := range out {
		if a := found[nick.Fold(h)]; a != nil {
			ident, dom := a.Identity(), a.HomeDomain
			id.Federated, id.Identity, id.HomeDomain = true, &ident, &dom
		}
	}
	return out, nil
}

// ---- admin ----------------------------------------------------------------

// ListUsers is the remote users list; cursor is the next_cursor of the
// previous page ("" = first page).
func (s *FederationService) ListUsers(ctx context.Context, f fedrepo.ListFilter, cursor string) ([]*fedrepo.AccountView, int64, string, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	f.Offset = 0
	if cursor != "" {
		n, err := strconv.Atoi(cursor)
		if err != nil || n < 0 {
			return nil, 0, "", apperr.InvalidField("cursor", "is not a cursor from this list")
		}
		f.Offset = n
	}
	list, total, err := s.Repo.List(ctx, f)
	if err != nil {
		return nil, 0, "", err
	}
	next := ""
	if int64(f.Offset+len(list)) < total && len(list) > 0 {
		next = strconv.Itoa(f.Offset + len(list))
	}
	return list, total, next, nil
}

// GetUser is one remote user.
func (s *FederationService) GetUser(ctx context.Context, userID string) (*fedrepo.AccountView, error) {
	v, err := s.Repo.View(ctx, userID)
	if errors.Is(err, repositories.ErrNotFound) {
		return nil, errNotFederated
	}
	return v, err
}

// Ban bans the identity behind remote user userID: it can't sign in again
// and its local account is disabled (sessions end, IRC drops it through
// the removed-accounts feed). An account an admin already disabled stays
// as it is.
func (s *FederationService) Ban(ctx context.Context, actorID, userID, reason string) (*fedrepo.AccountView, error) {
	reason = strings.TrimSpace(reason)
	if utf8.RuneCountInString(reason) > 500 || !textutil.Storable(reason) {
		return nil, apperr.InvalidField("reason", "must be at most 500 characters")
	}
	var a *fedrepo.Account
	revoked := int64(0)
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		var err error
		if a, err = s.Repo.FindByUserID(ctx, userID); errors.Is(err, repositories.ErrNotFound) {
			return errNotFederated
		} else if err != nil {
			return err
		}
		if err := s.Repo.Ban(ctx, &fedrepo.Ban{Issuer: a.Issuer, Subject: a.Subject, Identity: a.Identity(),
			Reason: reason, CreatedBy: ptr(actorID), CreatedAt: s.now()}); err != nil {
			return err
		}
		u, err := s.Users.FindByIDForUpdate(ctx, a.UserID)
		if err != nil {
			return err
		}
		if !u.Disabled() {
			now := s.now()
			if err := s.Users.SetDisabled(ctx, a.UserID, &now); err != nil {
				return err
			}
			by := fedrepo.SuspendedBan
			if err := s.Repo.SetSuspendedBy(ctx, a.UserID, &by); err != nil {
				return err
			}
		}
		revoked, err = s.Sessions.RevokeAll(ctx, a.UserID, "")
		return err
	})
	if err != nil {
		return nil, err
	}
	s.Audit.RecordTarget(ctx, actorID, userID, audit.EventFederationBanned, map[string]any{
		"identity": a.Identity(), "reason": reason, "sessions_revoked": revoked,
	})
	return s.GetUser(ctx, userID)
}

// Unban lifts a ban, re-enabling the account if the ban disabled it.
func (s *FederationService) Unban(ctx context.Context, actorID, userID string) (*fedrepo.AccountView, error) {
	var a *fedrepo.Account
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		var err error
		if a, err = s.Repo.FindByUserID(ctx, userID); errors.Is(err, repositories.ErrNotFound) {
			return errNotFederated
		} else if err != nil {
			return err
		}
		if err := s.Repo.Unban(ctx, a.Issuer, a.Subject); err != nil {
			return err
		}
		if a.SuspendedBy != nil && *a.SuspendedBy == fedrepo.SuspendedBan {
			if err := s.Users.SetDisabled(ctx, a.UserID, nil); err != nil {
				return err
			}
			return s.Repo.SetSuspendedBy(ctx, a.UserID, nil)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.Audit.RecordTarget(ctx, actorID, userID, audit.EventFederationUnbanned, map[string]any{"identity": a.Identity()})
	return s.GetUser(ctx, userID)
}

// ListBans lists banned identities.
func (s *FederationService) ListBans(ctx context.Context) ([]*fedrepo.Ban, error) {
	return s.Repo.ListBans(ctx)
}

// RevokeDomainSessions ends every session of the federated accounts from
// domain (or *.domain). Returns how many sessions ended.
func (s *FederationService) RevokeDomainSessions(ctx context.Context, actorID, domain string) (string, int64, error) {
	list, err := config.ParseDomainList([]string{domain})
	if err != nil || len(list) != 1 {
		return "", 0, apperr.InvalidField("domain", "must be a domain such as example.org")
	}
	entry := list[0]
	var total int64
	err = s.Tx.WithTx(ctx, func(ctx context.Context) error {
		accts, err := s.Repo.ByDomain(ctx, entry)
		if err != nil {
			return err
		}
		for _, a := range accts {
			n, err := s.Sessions.RevokeAll(ctx, a.UserID, "")
			if err != nil {
				return err
			}
			total += n
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	s.Audit.Record(ctx, actorID, audit.EventFederationSessionsRevoked, map[string]any{"domain": entry, "revoked": total})
	return entry, total, nil
}

// Cleanup prunes expired replay-cache entries.
func (s *FederationService) Cleanup(ctx context.Context) error {
	return s.Repo.PruneSeen(ctx, s.now())
}
