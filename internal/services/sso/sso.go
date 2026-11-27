// Package sso runs sign-in through external identity providers (OIDC and
// SAML): the browser flow (start → IdP → callback/ACS), the account linking
// rules, the one-time code exchange for native clients, provider
// administration and users' linked identities. See docs/sso.md.
package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/credential"
	"github.com/boson-chat/auth/internal/db/repositories/identity"
	"github.com/boson-chat/auth/internal/db/repositories/ssocode"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/keycrypt"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/opaque"
	"github.com/boson-chat/auth/internal/services/account"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/services/authn"
	"github.com/boson-chat/auth/internal/services/idp"
	"github.com/boson-chat/auth/internal/services/idp/oidc"
	"github.com/boson-chat/auth/internal/services/invite"
	"github.com/boson-chat/auth/internal/services/settings"
	"github.com/boson-chat/auth/internal/textutil"
	"github.com/boson-chat/auth/metrics"
)

// CodePrefix marks one-time SSO login codes.
const CodePrefix = "bsc_"

const (
	maxClaimsJSON  = 16 << 10
	reloadThrottle = 10 * time.Second
	checkTimeout   = 15 * time.Second
)

// Client-facing errors. After the flow has a return_to, the handler sends
// them back as ?error=<code>&error_description=<message>.
var (
	ErrUnknownProvider = apperr.New(http.StatusNotFound, "unknown_provider", "no such sign-in provider")
	ErrState           = apperr.New(http.StatusBadRequest, "invalid_state", "the sign-in expired or was started in another browser; please try again")
	ErrFailed          = apperr.New(http.StatusUnauthorized, "sso_failed", "the identity provider's response could not be verified")
	ErrAccessDenied    = apperr.New(http.StatusForbidden, "access_denied", "sign-in was cancelled or refused at the identity provider")
	ErrNoAccount       = apperr.New(http.StatusForbidden, "no_linked_account", "no account is linked to this sign-in, and sign-up through this provider is off")
	ErrLastLoginMethod = apperr.New(http.StatusConflict, "last_login_method", "this is your only way to sign in; set a password first")
	ErrInvalidCode     = apperr.New(http.StatusBadRequest, "invalid_code", "the sign-in code is invalid, expired or already used")
	ErrUnavailable     = apperr.New(http.StatusBadGateway, "idp_unavailable", "the identity provider can't be reached right now")
)

var (
	slugRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	challengeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)
)

// StartInput is GET /v1/sso/{slug}/start.
type StartInput struct {
	Slug, ReturnTo, Mode, InviteCode string
	// Optional client PKCE for code mode: S256 challenge of a verifier the
	// client sends to /v1/sso/exchange.
	CodeChallenge, CodeChallengeMethod string
}

// StartResult: send the browser to Login and set Cookie (the sealed state).
// On error ReturnTo is set when the error can be reported there.
type StartResult struct {
	Login    *idp.LoginRequest
	Cookie   string
	Kind     string
	ReturnTo string
}

// CompleteResult: in cookie mode Tokens is set, in code mode Code. ReturnTo
// is set whenever the state cookie was valid, also on error.
type CompleteResult struct {
	ReturnTo string
	Mode     string
	Tokens   *authn.Tokens
	Code     string
	Created  bool
}

// ProviderInput creates or (partially) updates a provider. In Config, the
// key client_secret is write-only (stored encrypted); null removes a key on
// update.
type ProviderInput struct {
	Slug        *string
	Kind        *string
	DisplayName *string
	Enabled     *bool
	AllowSignup *bool
	TrustEmail  *bool
	// SignupWhenClosed: AllowSignup also applies while registration is
	// closed or invite-only.
	SignupWhenClosed *bool
	Config           map[string]any
}

// ProviderView is a provider for the admin API. Secrets are never included.
type ProviderView struct {
	*identity.Provider
	HasClientSecret bool
	StartURL        string
	RedirectURI     string // OIDC
	ACSURL          string // SAML
	SPMetadataURL   string // SAML
	SPEntityID      string // SAML
}

type SSOServiceImpl interface {
	// Providers lists the enabled providers for login buttons.
	Providers(ctx context.Context) []idp.ProviderInfo
	Start(ctx context.Context, in StartInput) (*StartResult, error)
	// Complete finishes a flow: stateParam is the OIDC state or SAML
	// RelayState from the request, cookie the sealed state.
	Complete(ctx context.Context, slug string, r *http.Request, stateParam, cookie string) (*CompleteResult, error)
	// Exchange trades a one-time code (and the client's PKCE verifier, if it
	// sent a challenge) for a session.
	Exchange(ctx context.Context, code, verifier string) (*authn.Tokens, error)
	SAMLMetadata(ctx context.Context, slug string) ([]byte, error)

	ListProviders(ctx context.Context) ([]*ProviderView, error)
	GetProvider(ctx context.Context, id string) (*ProviderView, error)
	CreateProvider(ctx context.Context, actorID string, in ProviderInput) (*ProviderView, error)
	UpdateProvider(ctx context.Context, actorID, id string, in ProviderInput) (*ProviderView, error)
	DeleteProvider(ctx context.Context, actorID, id string) error
	// TestProvider checks the stored config against the IdP.
	TestProvider(ctx context.Context, id string) (bool, map[string]any, error)

	ListIdentities(ctx context.Context, userID string) ([]*identity.IdentityView, error)
	HasPassword(ctx context.Context, userID string) (bool, error)
	// UnlinkIdentity removes one of userID's identities, unless it's their
	// only way to sign in.
	UnlinkIdentity(ctx context.Context, userID, identityID string) error

	// Reload rebuilds the live providers from the database.
	Reload(ctx context.Context) error
	// Cleanup deletes expired login codes.
	Cleanup(ctx context.Context) error
}

type Deps struct {
	Identities  identity.IdentityRepositoryImpl
	Codes       ssocode.SSOCodeRepositoryImpl
	Users       user.UserRepositoryImpl
	Credentials credential.CredentialRepositoryImpl
	Tx          db.TxManagerImpl
	Registry    *idp.Registry
	Invites     invite.InviteServiceImpl
	Settings    settings.SettingsServiceImpl
	Authn       authn.AuthnServiceImpl
	Audit       audit.AuditServiceImpl
	Metrics     *metrics.Metrics
	ReturnTo    *ReturnToPolicy
	// AUTH_KEY_ENCRYPTION_KEY: encrypts provider secrets and (derived) the
	// state cookie.
	EncryptionKey []byte
	PublicURL     string
	StateTTL      time.Duration
	CodeTTL       time.Duration
	Now           func() time.Time
}

type SSOService struct {
	Deps
	stateKey []byte

	reloadMu   sync.Mutex
	lastReload time.Time
}

func NewSSOService(d Deps) (SSOServiceImpl, error) {
	if d.Now == nil {
		d.Now = time.Now
	}
	k, err := stateKey(d.EncryptionKey)
	if err != nil {
		return nil, err
	}
	return &SSOService{Deps: d, stateKey: k}, nil
}

func (s *SSOService) now() time.Time { return s.Now().UTC() }

func (s *SSOService) base(slug string) string { return s.PublicURL + "/v1/sso/" + slug }

// StartURL, CallbackURL, ACSURL and MetadataURL are a provider's endpoints.
func (s *SSOService) StartURL(slug string) string    { return s.base(slug) + "/start" }
func (s *SSOService) CallbackURL(slug string) string { return s.base(slug) + "/callback" }
func (s *SSOService) ACSURL(slug string) string      { return s.base(slug) + "/saml/acs" }
func (s *SSOService) MetadataURL(slug string) string { return s.base(slug) + "/saml/metadata" }

func notFound(err error, as error) error {
	if errors.Is(err, repositories.ErrNotFound) {
		return as
	}
	return err
}

// ---- live providers -------------------------------------------------------

func (s *SSOService) buildContext(p *identity.Provider) (idp.BuildContext, error) {
	bc := idp.BuildContext{CallbackURL: s.CallbackURL(p.Slug), ACSURL: s.ACSURL(p.Slug), MetadataURL: s.MetadataURL(p.Slug)}
	if len(p.ClientSecretEnc) > 0 {
		b, err := keycrypt.Open(s.EncryptionKey, p.ClientSecretEnc, []byte("client_secret:"+p.ID))
		if err != nil {
			return bc, err
		}
		bc.ClientSecret = string(b)
	}
	if len(p.SPKeyEnc) > 0 {
		der, err := keycrypt.Open(s.EncryptionKey, p.SPKeyEnc, []byte("sp_key:"+p.ID))
		if err != nil {
			return bc, err
		}
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return bc, err
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return bc, errors.New("sso: SP key is not RSA")
		}
		blk, _ := pem.Decode([]byte(p.SPCert))
		if blk == nil {
			return bc, errors.New("sso: SP certificate missing")
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return bc, err
		}
		bc.SPKey, bc.SPCert = rk, cert
	}
	return bc, nil
}

func (s *SSOService) build(p *identity.Provider) (idp.IdentityProvider, error) {
	k, ok := s.Registry.Kind(p.Kind)
	if !ok {
		return nil, apperr.Invalid("unsupported provider kind")
	}
	bc, err := s.buildContext(p)
	if err != nil {
		return nil, err
	}
	return k.Build(p, bc)
}

func (s *SSOService) Reload(ctx context.Context) error {
	rows, err := s.Identities.ListProviders(ctx, true)
	if err != nil {
		return err
	}
	s.Registry.Load(ctx, rows, s.buildContext)
	s.reloadMu.Lock()
	s.lastReload = s.now()
	s.reloadMu.Unlock()
	return nil
}

// live returns the provider for slug, reloading once (throttled) on a miss
// so a provider created on another replica works right away.
func (s *SSOService) live(ctx context.Context, slug string) (idp.IdentityProvider, error) {
	if p, err := s.Registry.Get(slug); err == nil {
		return p, nil
	}
	s.reloadMu.Lock()
	due := s.now().Sub(s.lastReload) > reloadThrottle
	s.reloadMu.Unlock()
	if due {
		if err := s.Reload(ctx); err != nil {
			return nil, err
		}
		if p, err := s.Registry.Get(slug); err == nil {
			return p, nil
		}
	}
	return nil, ErrUnknownProvider
}

func (s *SSOService) Providers(context.Context) []idp.ProviderInfo {
	list := s.Registry.List()
	for i := range list {
		list[i].StartURL = s.StartURL(list[i].Slug)
	}
	return list
}

// ---- login flow -----------------------------------------------------------

func (s *SSOService) Start(ctx context.Context, in StartInput) (*StartResult, error) {
	// A PKCE challenge only makes sense for the code flow: a client that sends
	// one without a mode (the Boson app on the server's own web origin, where
	// the automatic choice would be cookie) wants code.
	reqMode := in.Mode
	if reqMode == "" && in.CodeChallenge != "" {
		reqMode = ModeCode
	}
	rt, mode, err := s.ReturnTo.Resolve(in.ReturnTo, reqMode)
	if err != nil {
		return nil, err
	}
	res := &StartResult{ReturnTo: rt}
	if in.CodeChallenge != "" {
		if in.CodeChallengeMethod != "" && in.CodeChallengeMethod != "S256" {
			return res, apperr.Invalid("code_challenge_method must be S256")
		}
		if !challengeRE.MatchString(in.CodeChallenge) {
			return res, apperr.Invalid("code_challenge must be base64url (43-128 characters)")
		}
		if mode != ModeCode {
			return res, apperr.Invalid("code_challenge is only used with mode=code")
		}
	}
	if len(in.InviteCode) > 128 || !textutil.Storable(in.InviteCode) {
		return res, apperr.ErrInviteRequired
	}
	if !slugRE.MatchString(in.Slug) {
		return res, ErrUnknownProvider
	}
	p, err := s.live(ctx, in.Slug)
	if err != nil {
		return res, err
	}
	state := opaque.New("")
	lr, err := p.BeginLogin(ctx, state)
	if err != nil {
		logger.FromCtx(ctx).Error().Err(err).Str("slug", in.Slug).Msg("sso start")
		return res, ErrUnavailable
	}
	cookie, err := sealState(s.stateKey, flowState{
		Slug: in.Slug, State: state, Saved: lr.Saved, ReturnTo: rt, Mode: mode,
		Invite: in.InviteCode, Challenge: in.CodeChallenge, Exp: s.now().Add(s.StateTTL).Unix(),
	})
	if err != nil {
		return res, err
	}
	res.Login, res.Cookie, res.Kind = lr, cookie, p.Kind()
	return res, nil
}

func (s *SSOService) Complete(ctx context.Context, slug string, r *http.Request, stateParam, cookie string) (*CompleteResult, error) {
	fs, err := openState(s.stateKey, cookie, s.now())
	if err != nil || fs.Slug != slug || subtle.ConstantTimeCompare([]byte(fs.State), []byte(stateParam)) != 1 {
		return nil, ErrState
	}
	res := &CompleteResult{ReturnTo: fs.ReturnTo, Mode: fs.Mode}
	p, err := s.live(ctx, slug)
	if err != nil {
		return res, err
	}
	row, err := s.Identities.FindProviderBySlug(ctx, slug)
	if err != nil {
		return res, notFound(err, ErrUnknownProvider)
	}
	kind := p.Kind()
	x, err := p.CompleteLogin(ctx, r, fs.Saved)
	if err != nil {
		var idpErr *oidc.ErrIdP
		if errors.As(err, &idpErr) {
			s.Metrics.LoginAttempt(ctx, kind, metrics.OutcomeRejected)
			return res, ErrAccessDenied
		}
		logger.FromCtx(ctx).Warn().Err(err).Str("slug", slug).Msg("sso response rejected")
		s.Metrics.LoginAttempt(ctx, kind, metrics.OutcomeInvalidCredentials)
		s.Audit.Record(ctx, "", audit.EventSSOFailed, map[string]any{"provider": slug, "reason": "invalid_response"})
		return res, ErrFailed
	}
	u, created, err := s.linkOrCreate(ctx, row, x, fs.Invite)
	if err != nil {
		if e, ok := apperr.As(err); ok {
			s.Metrics.LoginAttempt(ctx, kind, metrics.OutcomeRejected)
			uid := ""
			if u != nil {
				uid = u.ID
			}
			s.Audit.Record(ctx, uid, audit.EventSSOFailed, map[string]any{"provider": slug, "reason": e.Code})
		}
		return res, err
	}
	res.Created = created
	method := kind + ":" + slug
	if fs.Mode == ModeCookie {
		res.Tokens, err = s.Authn.IssueSession(ctx, u, method)
		return res, err
	}
	raw := opaque.New(CodePrefix)
	now := s.now()
	err = s.Codes.Create(ctx, &ssocode.Code{
		ID: ids.New(ids.SSOCode), CodeHash: opaque.Hash(raw), UserID: u.ID, ProviderID: row.ID,
		AuthMethod: method, CodeChallenge: fs.Challenge, ExpiresAt: now.Add(s.CodeTTL), CreatedAt: now,
	})
	if err != nil {
		return res, err
	}
	res.Code = raw
	return res, nil
}

func (s *SSOService) Exchange(ctx context.Context, code, verifier string) (*authn.Tokens, error) {
	if !strings.HasPrefix(code, CodePrefix) || len(code) > 128 || len(verifier) > 128 {
		return nil, ErrInvalidCode
	}
	c, err := s.Codes.Consume(ctx, opaque.Hash(code), s.now())
	if err != nil {
		return nil, notFound(err, ErrInvalidCode)
	}
	if c.CodeChallenge != "" {
		sum := sha256.Sum256([]byte(verifier))
		got := base64.RawURLEncoding.EncodeToString(sum[:])
		if verifier == "" || subtle.ConstantTimeCompare([]byte(got), []byte(c.CodeChallenge)) != 1 {
			return nil, ErrInvalidCode
		}
	}
	u, err := s.Users.FindByID(ctx, c.UserID)
	if err != nil {
		return nil, notFound(err, ErrInvalidCode)
	}
	return s.Authn.IssueSession(ctx, u, c.AuthMethod)
}

// cleanClaims makes claims storable in jsonb (no NUL, valid UTF-8, bounded).
func cleanClaims(v any, depth int) any {
	switch t := v.(type) {
	case string:
		return textutil.Clean(t, 2048)
	case map[string]any:
		if depth > 5 {
			return nil
		}
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[textutil.Clean(k, 256)] = cleanClaims(val, depth+1)
		}
		return out
	case []any:
		if depth > 5 {
			return nil
		}
		out := make([]any, 0, min(len(t), 100))
		for i, val := range t {
			if i == 100 {
				break
			}
			out = append(out, cleanClaims(val, depth+1))
		}
		return out
	case []string:
		out := make([]any, 0, len(t))
		for _, val := range t {
			out = append(out, textutil.Clean(val, 2048))
		}
		return out
	}
	return v
}

func storableClaims(c map[string]any) repositories.JSONB {
	clean, _ := cleanClaims(c, 0).(map[string]any)
	if b, err := json.Marshal(clean); err != nil || len(b) > maxClaimsJSON {
		return repositories.JSONB{"_truncated": true}
	}
	return clean
}

// linkOrCreate applies the rules in docs/sso.md. On a lost race (two
// callbacks creating the same user) it retries; the second finds the first's
// identity.
func (s *SSOService) linkOrCreate(ctx context.Context, row *identity.Provider, x idp.ExternalIdentity, inviteCode string) (*user.User, bool, error) {
	if x.Subject == "" || len(x.Subject) > 512 || !textutil.Storable(x.Subject) {
		return nil, false, ErrFailed
	}
	addr := ""
	if a, err := account.NormalizeEmail(x.Email); err == nil {
		addr = a
	}
	claims := storableClaims(x.Claims)
	var idEmail *string
	if addr != "" {
		idEmail = &addr
	}
	var (
		u       *user.User
		created bool
		linked  bool
		err     error
	)
	for attempt := range 4 {
		u, created, linked = nil, false, false
		err = s.Tx.WithTx(ctx, func(ctx context.Context) error {
			now := s.now()
			// 1. Known identity.
			ident, err := s.Identities.FindIdentity(ctx, row.ID, x.Subject)
			if err == nil {
				if u, err = s.Users.FindByID(ctx, ident.UserID); err != nil {
					return err
				}
				if u.Disabled() {
					return apperr.ErrAccountDisabled
				}
				return s.Identities.TouchIdentity(ctx, ident.ID, now, idEmail, claims)
			}
			if !errors.Is(err, repositories.ErrNotFound) {
				return err
			}
			newIdentity := func(userID string) error {
				return s.Identities.CreateIdentity(ctx, &identity.UserIdentity{
					ID: ids.New(ids.Identity), UserID: userID, ProviderID: row.ID, Subject: x.Subject,
					Email: idEmail, RawClaims: claims, CreatedAt: now, LastLoginAt: &now,
				})
			}
			// 2. Verified email at a trusted IdP matches an account whose own
			// email is verified. An unverified match could be someone squatting
			// the address with a password they know, so it is never linked.
			trusted := row.TrustEmail && x.EmailVerified && addr != ""
			emailFree := addr != ""
			if trusted {
				eu, err := s.Users.FindByEmail(ctx, addr)
				switch {
				case err == nil && eu.EmailVerified():
					if eu.Disabled() {
						u = eu
						return apperr.ErrAccountDisabled
					}
					u, linked = eu, true
					return newIdentity(eu.ID)
				case err == nil:
					emailFree = false
				case !errors.Is(err, repositories.ErrNotFound):
					return err
				}
			}
			// 3. Sign-up.
			if !row.AllowSignup {
				return ErrNoAccount
			}
			st, err := s.Settings.Get(ctx)
			if err != nil {
				return err
			}
			switch {
			case row.SignupWhenClosed:
				// The provider is the gate: an account there is the invitation.
			case st.Registration == config.RegistrationClosed:
				return apperr.ErrRegistrationClosed
			case st.Registration == config.RegistrationInvite:
				if err := s.Invites.Redeem(ctx, inviteCode); err != nil {
					return err
				}
			}
			name, err := s.pickUsername(ctx, x, addr, attempt)
			if err != nil {
				return err
			}
			display, _ := account.CleanDisplayName(x.DisplayName)
			nu := &user.User{
				ID: ids.New(ids.User), Username: name, UsernameFolded: nick.Fold(name),
				DisplayName: display, Role: user.RoleUser, CreatedAt: now, UpdatedAt: now,
			}
			// The account email is set (and verified) only when the IdP is
			// trusted and asserts it verified; otherwise it stays on the identity.
			if trusted && emailFree {
				nu.Email, nu.EmailVerifiedAt = &addr, &now
			}
			if err := s.Users.Create(ctx, nu); err != nil {
				return err
			}
			u, created = nu, true
			return newIdentity(nu.ID)
		})
		if errors.Is(err, user.ErrUsernameTaken) || errors.Is(err, user.ErrEmailTaken) || errors.Is(err, identity.ErrIdentityTaken) {
			continue
		}
		break
	}
	if err != nil {
		return u, false, err
	}
	method := row.Kind + ":" + row.Slug
	switch {
	case created:
		s.Metrics.Registration(ctx, metrics.OutcomeSuccess)
		s.Audit.Record(ctx, u.ID, audit.EventRegister, map[string]any{"method": method})
	case linked:
		s.Audit.Record(ctx, u.ID, audit.EventSSOLinked, map[string]any{"provider": row.Slug, "reason": "trusted_email"})
	}
	return u, created, nil
}

// pickUsername derives a free, valid nick from the IdP's claims.
func (s *SSOService) pickUsername(ctx context.Context, x idp.ExternalIdentity, addr string, attempt int) (string, error) {
	local, _, _ := strings.Cut(addr, "@")
	base := ""
	for _, c := range []string{x.PreferredUsername, local, x.DisplayName, "user"} {
		if base = nick.Sanitize(c); base != "" {
			break
		}
	}
	free := func(n string) (bool, error) {
		_, err := s.Users.FindByUsernameFolded(ctx, nick.Fold(n))
		if errors.Is(err, repositories.ErrNotFound) {
			return true, nil
		}
		return false, err
	}
	withSuffix := func(sfx string) string {
		b := base
		if len(b)+len(sfx) > nick.MaxLen {
			b = b[:nick.MaxLen-len(sfx)]
		}
		return b + sfx
	}
	if attempt == 0 {
		if ok, err := free(base); err != nil || ok {
			return base, err
		}
		for n := 2; n <= 20; n++ {
			c := withSuffix(strconv.Itoa(n))
			if ok, err := free(c); err != nil || ok {
				return c, err
			}
		}
	}
	for range 10 {
		n, err := rand.Int(rand.Reader, big.NewInt(90000))
		if err != nil {
			return "", err
		}
		c := withSuffix(strconv.Itoa(10000 + int(n.Int64())))
		if ok, err := free(c); err != nil || ok {
			return c, err
		}
	}
	return "", errors.New("sso: no free username")
}

// ---- SAML SP metadata -----------------------------------------------------

func (s *SSOService) SAMLMetadata(ctx context.Context, slug string) ([]byte, error) {
	row, err := s.Identities.FindProviderBySlug(ctx, slug)
	if err != nil {
		return nil, notFound(err, ErrUnknownProvider)
	}
	if row.Kind != identity.KindSAML {
		return nil, ErrUnknownProvider
	}
	p, err := s.build(row)
	if err != nil {
		return nil, err
	}
	md, ok := p.(idp.SPMetadata)
	if !ok {
		return nil, ErrUnknownProvider
	}
	return md.Metadata()
}

// ---- admin ----------------------------------------------------------------

func (s *SSOService) view(p *identity.Provider) *ProviderView {
	v := &ProviderView{Provider: p, HasClientSecret: len(p.ClientSecretEnc) > 0, StartURL: s.StartURL(p.Slug)}
	switch p.Kind {
	case identity.KindOIDC:
		v.RedirectURI = s.CallbackURL(p.Slug)
	case identity.KindSAML:
		v.ACSURL, v.SPMetadataURL = s.ACSURL(p.Slug), s.MetadataURL(p.Slug)
		v.SPEntityID = v.SPMetadataURL
		if e, _ := p.Config["entity_id"].(string); e != "" {
			v.SPEntityID = e
		}
	}
	return v
}

func (s *SSOService) ListProviders(ctx context.Context) ([]*ProviderView, error) {
	rows, err := s.Identities.ListProviders(ctx, false)
	if err != nil {
		return nil, err
	}
	out := make([]*ProviderView, 0, len(rows))
	for _, r := range rows {
		out = append(out, s.view(r))
	}
	return out, nil
}

func (s *SSOService) GetProvider(ctx context.Context, id string) (*ProviderView, error) {
	p, err := s.Identities.FindProviderByID(ctx, id)
	if err != nil {
		return nil, notFound(err, apperr.ErrNotFound)
	}
	return s.view(p), nil
}

// newSPKey makes the SAML SP signing key and a 10-year self-signed certificate.
func newSPKey(slug string, now time.Time) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "boson SAML SP " + slug},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// applyConfig merges in.Config into cur, pulls out the write-only
// client_secret, and normalizes the result for the provider's kind.
func (s *SSOService) applyConfig(p *identity.Provider, cur map[string]any, patch map[string]any, replace bool) (secret *string, err error) {
	merged := map[string]any{}
	if !replace {
		for k, v := range cur {
			merged[k] = v
		}
	}
	for k, v := range patch {
		switch k {
		case "client_secret":
			if p.Kind != identity.KindOIDC {
				return nil, apperr.Invalid("client_secret only applies to oidc providers")
			}
			str, ok := v.(string)
			if v != nil && !ok {
				return nil, apperr.Invalid("client_secret must be a string")
			}
			if len(str) > 1024 || !textutil.Storable(str) {
				return nil, apperr.Invalid("client_secret is too long")
			}
			secret = &str
			continue
		case "has_client_secret":
			continue // echoed back from a GET; read-only
		}
		if v == nil {
			delete(merged, k)
		} else {
			merged[k] = v
		}
	}
	k, ok := s.Registry.Kind(p.Kind)
	if !ok {
		return nil, apperr.Invalid("kind must be oidc or saml")
	}
	norm, err := k.Normalize(merged)
	if err != nil {
		return nil, err
	}
	p.Config = norm
	return secret, nil
}

func (s *SSOService) setSecret(p *identity.Provider, secret *string) error {
	if secret == nil {
		return nil
	}
	if *secret == "" {
		p.ClientSecretEnc = nil
		return nil
	}
	enc, err := keycrypt.Seal(s.EncryptionKey, []byte(*secret), []byte("client_secret:"+p.ID))
	p.ClientSecretEnc = enc
	return err
}

func validateFields(p *identity.Provider) error {
	if !slugRE.MatchString(p.Slug) {
		return apperr.Invalid("slug must be 1-32 characters of a-z, 0-9 and -, starting with a letter or digit")
	}
	p.DisplayName = strings.TrimSpace(p.DisplayName)
	if p.DisplayName == "" {
		p.DisplayName = p.Slug
	}
	if n, err := account.CleanDisplayName(p.DisplayName); err != nil || n == "" {
		return apperr.Invalid("display_name must be 1-64 printable characters")
	}
	return nil
}

var errSlugTaken = apperr.New(http.StatusConflict, "slug_taken", "a provider with that slug already exists")

func (s *SSOService) CreateProvider(ctx context.Context, actorID string, in ProviderInput) (*ProviderView, error) {
	if in.Slug == nil || in.Kind == nil {
		return nil, apperr.Invalid("slug and kind are required")
	}
	now := s.now()
	p := &identity.Provider{ID: ids.New(ids.Provider), Kind: *in.Kind, Slug: *in.Slug, CreatedAt: now, UpdatedAt: now}
	if p.Kind != identity.KindOIDC && p.Kind != identity.KindSAML {
		return nil, apperr.Invalid("kind must be oidc or saml")
	}
	if in.DisplayName != nil {
		p.DisplayName = *in.DisplayName
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	if in.AllowSignup != nil {
		p.AllowSignup = *in.AllowSignup
	}
	if in.TrustEmail != nil {
		p.TrustEmail = *in.TrustEmail
	}
	if in.SignupWhenClosed != nil {
		p.SignupWhenClosed = *in.SignupWhenClosed
	}
	if err := validateFields(p); err != nil {
		return nil, err
	}
	secret, err := s.applyConfig(p, nil, in.Config, true)
	if err != nil {
		return nil, err
	}
	if err := s.setSecret(p, secret); err != nil {
		return nil, err
	}
	if p.Kind == identity.KindSAML {
		key, certPEM, err := newSPKey(p.Slug, now)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		if p.SPKeyEnc, err = keycrypt.Seal(s.EncryptionKey, der, []byte("sp_key:"+p.ID)); err != nil {
			return nil, err
		}
		p.SPCert = string(certPEM)
	}
	if err := s.Identities.CreateProvider(ctx, p); err != nil {
		if errors.Is(err, identity.ErrSlugTaken) {
			return nil, errSlugTaken
		}
		return nil, err
	}
	s.Audit.Record(ctx, actorID, audit.EventSSOProviderCreated, map[string]any{"provider_id": p.ID, "slug": p.Slug, "kind": p.Kind, "enabled": p.Enabled})
	s.reloadAfterChange(ctx)
	return s.view(p), nil
}

func (s *SSOService) UpdateProvider(ctx context.Context, actorID, id string, in ProviderInput) (*ProviderView, error) {
	p, err := s.Identities.FindProviderByID(ctx, id)
	if err != nil {
		return nil, notFound(err, apperr.ErrNotFound)
	}
	if in.Kind != nil && *in.Kind != p.Kind {
		return nil, apperr.Invalid("kind can't be changed; create a new provider")
	}
	changed := []string{}
	if in.Slug != nil && *in.Slug != p.Slug {
		p.Slug, changed = *in.Slug, append(changed, "slug")
	}
	if in.DisplayName != nil {
		p.DisplayName, changed = *in.DisplayName, append(changed, "display_name")
	}
	if in.Enabled != nil {
		p.Enabled, changed = *in.Enabled, append(changed, "enabled")
	}
	if in.AllowSignup != nil {
		p.AllowSignup, changed = *in.AllowSignup, append(changed, "allow_signup")
	}
	if in.TrustEmail != nil {
		p.TrustEmail, changed = *in.TrustEmail, append(changed, "trust_email")
	}
	if in.SignupWhenClosed != nil {
		p.SignupWhenClosed, changed = *in.SignupWhenClosed, append(changed, "signup_when_closed")
	}
	if err := validateFields(p); err != nil {
		return nil, err
	}
	if in.Config != nil {
		secret, err := s.applyConfig(p, p.Config, in.Config, false)
		if err != nil {
			return nil, err
		}
		if err := s.setSecret(p, secret); err != nil {
			return nil, err
		}
		changed = append(changed, "config")
		if secret != nil {
			changed = append(changed, "client_secret")
		}
	}
	if len(changed) == 0 {
		return nil, apperr.Invalid("nothing to update")
	}
	// updated_at is what makes every replica rebuild the provider.
	p.UpdatedAt = s.now()
	if err := s.Identities.UpdateProvider(ctx, p); err != nil {
		if errors.Is(err, identity.ErrSlugTaken) {
			return nil, errSlugTaken
		}
		return nil, notFound(err, apperr.ErrNotFound)
	}
	s.Audit.Record(ctx, actorID, audit.EventSSOProviderUpdated, map[string]any{"provider_id": p.ID, "slug": p.Slug, "fields": changed})
	s.reloadAfterChange(ctx)
	return s.view(p), nil
}

func (s *SSOService) DeleteProvider(ctx context.Context, actorID, id string) error {
	p, err := s.Identities.FindProviderByID(ctx, id)
	if err != nil {
		return notFound(err, apperr.ErrNotFound)
	}
	if err := s.Identities.DeleteProvider(ctx, id); err != nil {
		return notFound(err, apperr.ErrNotFound)
	}
	s.Audit.Record(ctx, actorID, audit.EventSSOProviderDeleted, map[string]any{"provider_id": id, "slug": p.Slug})
	s.reloadAfterChange(ctx)
	return nil
}

func (s *SSOService) reloadAfterChange(ctx context.Context) {
	if err := s.Reload(ctx); err != nil {
		logger.FromCtx(ctx).Warn().Err(err).Msg("reloading identity providers")
	}
}

func (s *SSOService) TestProvider(ctx context.Context, id string) (bool, map[string]any, error) {
	row, err := s.Identities.FindProviderByID(ctx, id)
	if err != nil {
		return false, nil, notFound(err, apperr.ErrNotFound)
	}
	p, err := s.build(row)
	if err != nil {
		return false, map[string]any{"error": err.Error()}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	details, err := p.Check(ctx)
	if details == nil {
		details = map[string]any{}
	}
	if err != nil {
		details["error"] = err.Error()
		return false, details, nil
	}
	return true, details, nil
}

// ---- identities -----------------------------------------------------------

func (s *SSOService) ListIdentities(ctx context.Context, userID string) ([]*identity.IdentityView, error) {
	return s.Identities.ListIdentitiesByUser(ctx, userID)
}

func (s *SSOService) HasPassword(ctx context.Context, userID string) (bool, error) {
	_, err := s.Credentials.Get(ctx, userID)
	if errors.Is(err, repositories.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (s *SSOService) UnlinkIdentity(ctx context.Context, userID, identityID string) error {
	if !textutil.Storable(identityID) {
		return apperr.ErrNotFound
	}
	var slug string
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		// The row lock serialises concurrent unlinks of the same user.
		if _, err := s.Users.FindByIDForUpdate(ctx, userID); err != nil {
			return notFound(err, apperr.ErrNotFound)
		}
		list, err := s.Identities.ListIdentitiesByUser(ctx, userID)
		if err != nil {
			return err
		}
		found := false
		for _, i := range list {
			if i.ID == identityID {
				found, slug = true, i.ProviderSlug
			}
		}
		if !found {
			return apperr.ErrNotFound
		}
		hasPW, err := s.HasPassword(ctx, userID)
		if err != nil {
			return err
		}
		if !hasPW && len(list) <= 1 {
			return ErrLastLoginMethod
		}
		return s.Identities.DeleteIdentity(ctx, userID, identityID)
	})
	if err != nil {
		return err
	}
	s.Audit.Record(ctx, userID, audit.EventSSOUnlinked, map[string]any{"identity_id": identityID, "provider": slug})
	return nil
}

func (s *SSOService) Cleanup(ctx context.Context) error {
	_, err := s.Codes.DeleteExpiredBefore(ctx, s.now().Add(-time.Hour))
	return err
}
