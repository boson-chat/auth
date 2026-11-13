// Package token mints and verifies the service's JWTs.
//
// Access token (aud "boson"), header {alg: EdDSA, kid, typ: "at+jwt"}:
//
//	iss sub aud sid name role iat nbf exp jti
//
// Voice token (aud "quicvoice"), header {alg: EdDSA, kid, typ: "JWT"}:
//
//	iss sub aud sid name role rooms? iat nbf exp jti
//
// Both are verifiable with the JWKS at /.well-known/jwks.json. The distinct
// audiences (and typ for access tokens) stop one being used as the other.
package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/ids"
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

// AccessClaims are the verified contents of an access token.
type AccessClaims struct {
	Subject   string
	SessionID string
	Name      string
	Role      string
	ID        string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type TokenServiceImpl interface {
	MintAccess(ctx context.Context, u *user.User, sessionID string) (string, time.Time, error)
	VerifyAccess(ctx context.Context, raw string) (*AccessClaims, error)
	MintVoice(ctx context.Context, u *user.User, sessionID string, rooms []string) (string, time.Time, error)
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

func (s *TokenService) MintAccess(ctx context.Context, u *user.User, sessionID string) (string, time.Time, error) {
	if u == nil || u.ID == "" || sessionID == "" {
		return "", time.Time{}, errors.New("token: missing subject or session")
	}
	c, exp := s.base(u, sessionID, AudienceBoson, s.opts.AccessTTL)
	c["role"] = u.Role
	tok, err := s.sign(ctx, TypAccess, c)
	return tok, exp, err
}

// VoiceRole maps an account role to a quicvoiced role.
func VoiceRole(role string) string {
	if role == user.RoleAdmin {
		return VoiceRoleModerator
	}
	return VoiceRoleSpeaker
}

func (s *TokenService) MintVoice(ctx context.Context, u *user.User, sessionID string, rooms []string) (string, time.Time, error) {
	if u == nil || u.ID == "" {
		return "", time.Time{}, errors.New("token: missing subject")
	}
	c, exp := s.base(u, sessionID, AudienceQuicvoice, s.opts.VoiceTTL)
	c["role"] = VoiceRole(u.Role)
	if len(rooms) > 0 {
		c["rooms"] = rooms
	}
	tok, err := s.sign(ctx, "JWT", c)
	return tok, exp, err
}

type accessJWT struct {
	SID  string `json:"sid"`
	Name string `json:"name"`
	Role string `json:"role"`
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
	out := &AccessClaims{Subject: c.Subject, SessionID: c.SID, Name: c.Name, Role: c.Role, ID: c.ID}
	if c.IssuedAt != nil {
		out.IssuedAt = c.IssuedAt.Time
	}
	if c.ExpiresAt != nil {
		out.ExpiresAt = c.ExpiresAt.Time
	}
	return out, nil
}
