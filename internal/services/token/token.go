// Package token mints and verifies the service's JWTs.
//
// Access token (aud "boson"), header {alg: EdDSA, kid, typ: "at+jwt"}:
//
//	iss sub aud sid name role roles? perms iat nbf exp jti
//
// Voice token (aud "quicvoice"), header {alg: EdDSA, kid, typ: "JWT"}:
//
//	iss sub aud sid name role roles? perms rooms? iat nbf exp jti
//
// Guest voice token (aud "quicvoice", POST /v1/voice/guest-token), for a
// guest on IRC with no account:
//
//	iss sub="guest:<guest_id>" aud name=<IRC nick, unverified> guest=true
//	role="speaker" roles=[] perms=[] rooms? iat nbf exp jti
//
// (no sid; roles and perms are always present and empty).
//
// role is the 1.x compatibility claim (admin iff admin.panel; speaker or
// moderator on voice tokens), roles the assigned role names (most senior
// first, at most 20, omitted when none), perms the effective permissions
// (voice tokens: only the network group).
//
// Both are verifiable with the JWKS at /.well-known/jwks.json. The distinct
// audiences (and typ for access tokens) stop one being used as the other.
package token

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/perm"
	"github.com/boson-chat/auth/internal/services/keys"
	"github.com/golang-jwt/jwt/v5"
)

const (
	AudienceBoson     = "boson"
	AudienceQuicvoice = "quicvoice"
	TypAccess         = "at+jwt"
	leeway            = 30 * time.Second
)

// quicvoiced roles: listener < speaker < moderator < admin.
const (
	VoiceRoleSpeaker   = "speaker"
	VoiceRoleModerator = "moderator"
)

var ErrInvalidToken = errors.New("token: invalid")

// Grants are the role-derived claims of a token.
type Grants struct {
	Roles []string // assigned role names, most senior first
	Perms []string // effective permissions
}

func (g Grants) Has(p string) bool { return slices.Contains(g.Perms, p) }

// LegacyRole is the 1.x role claim: admin iff the user may open the admin panel.
func (g Grants) LegacyRole() string {
	if g.Has(perm.AdminPanel) {
		return user.RoleAdmin
	}
	return user.RoleUser
}

// AccessClaims are the verified contents of an access token.
type AccessClaims struct {
	Subject   string
	SessionID string
	Name      string
	Role      string
	Roles     []string
	Perms     []string
	ID        string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type TokenServiceImpl interface {
	MintAccess(ctx context.Context, u *user.User, sessionID string, g Grants) (string, time.Time, error)
	VerifyAccess(ctx context.Context, raw string) (*AccessClaims, error)
	MintVoice(ctx context.Context, u *user.User, sessionID string, rooms []string, g Grants) (string, time.Time, error)
	// MintGuestVoice mints a voice token for a guest (no account): sub
	// GuestSubjectPrefix+guestID, name = nick, guest = true, role speaker,
	// empty roles and perms.
	MintGuestVoice(ctx context.Context, guestID, nick string, rooms []string) (string, time.Time, error)
}

type Options struct {
	Issuer    string
	AccessTTL time.Duration
	VoiceTTL  time.Duration
	Now       func() time.Time
}

type TokenService struct {
	Keys keys.KeyServiceImpl
	opts Options
}

func NewTokenService(k keys.KeyServiceImpl, opts Options) TokenServiceImpl {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &TokenService{Keys: k, opts: opts}
}

func (s *TokenService) sign(ctx context.Context, typ string, claims jwt.MapClaims) (string, error) {
	kid, priv, err := s.Keys.SigningKey(ctx)
	if err != nil {
		return "", err
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	t.Header["kid"] = kid
	t.Header["typ"] = typ
	return t.SignedString(priv)
}

func (s *TokenService) base(u *user.User, sessionID, aud string, ttl time.Duration) (jwt.MapClaims, time.Time) {
	now := s.opts.Now().UTC().Truncate(time.Second)
	exp := now.Add(ttl)
	return jwt.MapClaims{
		"iss":  s.opts.Issuer,
		"sub":  u.ID,
		"aud":  aud, // a single string, not an array
		"sid":  sessionID,
		"name": u.Username,
		"iat":  now.Unix(),
		"nbf":  now.Unix(),
		"exp":  exp.Unix(),
		"jti":  ids.New(ids.TokenID),
	}, exp
}

func addGrants(c jwt.MapClaims, roles, perms []string) {
	if len(roles) > 0 {
		c["roles"] = roles
	}
	if perms == nil {
		perms = []string{}
	}
	c["perms"] = perms
}

func (s *TokenService) MintAccess(ctx context.Context, u *user.User, sessionID string, g Grants) (string, time.Time, error) {
	if u == nil || u.ID == "" || sessionID == "" {
		return "", time.Time{}, errors.New("token: missing subject or session")
	}
	c, exp := s.base(u, sessionID, AudienceBoson, s.opts.AccessTTL)
	c["role"] = g.LegacyRole()
	addGrants(c, g.Roles, g.Perms)
	tok, err := s.sign(ctx, TypAccess, c)
	return tok, exp, err
}

// VoiceRole maps grants to a quicvoiced role: moderator with voice.manage_any.
func VoiceRole(g Grants) string {
	if g.Has(perm.VoiceManageAny) {
		return VoiceRoleModerator
	}
	return VoiceRoleSpeaker
}

func (s *TokenService) MintVoice(ctx context.Context, u *user.User, sessionID string, rooms []string, g Grants) (string, time.Time, error) {
	if u == nil || u.ID == "" {
		return "", time.Time{}, errors.New("token: missing subject")
	}
	c, exp := s.base(u, sessionID, AudienceQuicvoice, s.opts.VoiceTTL)
	c["role"] = VoiceRole(g)
	addGrants(c, g.Roles, perm.Filter(g.Perms, perm.GroupNetwork))
	if len(rooms) > 0 {
		c["rooms"] = rooms
	}
	tok, err := s.sign(ctx, "JWT", c)
	return tok, exp, err
}

// GuestSubjectPrefix starts the sub claim of guest voice tokens.
const GuestSubjectPrefix = "guest:"

func (s *TokenService) MintGuestVoice(ctx context.Context, guestID, nick string, rooms []string) (string, time.Time, error) {
	if guestID == "" || nick == "" {
		return "", time.Time{}, errors.New("token: missing guest id or nick")
	}
	now := s.opts.Now().UTC().Truncate(time.Second)
	exp := now.Add(s.opts.VoiceTTL)
	c := jwt.MapClaims{
		"iss":   s.opts.Issuer,
		"sub":   GuestSubjectPrefix + guestID,
		"aud":   AudienceQuicvoice,
		"name":  nick,
		"guest": true,
		"role":  VoiceRoleSpeaker,
		"roles": []string{},
		"perms": []string{},
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   exp.Unix(),
		"jti":   ids.New(ids.TokenID),
	}
	if len(rooms) > 0 {
		c["rooms"] = rooms
	}
	tok, err := s.sign(ctx, "JWT", c)
	return tok, exp, err
}

type accessJWT struct {
	SID   string   `json:"sid"`
	Name  string   `json:"name"`
	Role  string   `json:"role"`
	Roles []string `json:"roles"`
	Perms []string `json:"perms"`
	jwt.RegisteredClaims
}

func (s *TokenService) VerifyAccess(ctx context.Context, raw string) (*AccessClaims, error) {
	var c accessJWT
	_, err := jwt.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		if typ, _ := t.Header["typ"].(string); typ != TypAccess {
			return nil, fmt.Errorf("unexpected typ %q", typ)
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return s.Keys.PublicKey(ctx, kid)
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(s.opts.Issuer),
		jwt.WithAudience(AudienceBoson),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(leeway),
		jwt.WithTimeFunc(s.opts.Now),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if c.Subject == "" || c.SID == "" {
		return nil, fmt.Errorf("%w: missing sub or sid", ErrInvalidToken)
	}
	out := &AccessClaims{Subject: c.Subject, SessionID: c.SID, Name: c.Name, Role: c.Role, Roles: c.Roles, Perms: c.Perms, ID: c.ID}
	if c.IssuedAt != nil {
		out.IssuedAt = c.IssuedAt.Time
	}
	if c.ExpiresAt != nil {
		out.ExpiresAt = c.ExpiresAt.Time
	}
	return out, nil
}
