// Package workload is the workload issuer, <ISSUER>/workload: short-lived
// ES256 JWTs naming one of this stack's own services, for the service to
// present to an outside token exchange. The use it was built for is
// Google Workload Identity Federation: the push relay trades the token
// for a Google access token (STS, then service-account impersonation), so
// no Google service-account key exists anywhere.
//
// Token, header {alg: ES256, kid, typ: "JWT"}:
//
//	iss = <ISSUER>/workload   sub = service:<name>   aud = <audience>
//	iat   exp (iat + WORKLOAD_TOKEN_TTL, at most 10 min)   jti
//
// Only the (name, audience) pairs in WORKLOAD_IDENTITIES are minted, and a
// workload proves its name with its own secret (WORKLOAD_TOKEN_<NAME>).
// The keys, JWKS and discovery document are separate from the user-token
// ones: GET <ISSUER>/workload/.well-known/openid-configuration and
// GET <ISSUER>/workload/jwks.json.
package workload

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/golang-jwt/jwt/v5"
)

// PathPrefix is the issuer's path under ISSUER (and the public routes').
const PathPrefix = "/workload"

var (
	// ErrUnknownWorkload: no workload has the presented secret.
	ErrUnknownWorkload = errors.New("workload: unknown workload token")
	// ErrAudience: the audience is not configured for this workload, or
	// none was given and the workload has several.
	ErrAudience = errors.New("workload: audience not allowed")
)

type identity struct {
	config.WorkloadIdentity
	tokenSum [sha256.Size]byte
}

// Service mints workload tokens.
type Service struct {
	Keys       *KeySet
	issuer     string
	ttl        time.Duration
	identities []identity
	now        func() time.Time
}

// Token is a minted workload token.
type Token struct {
	JWT       string
	Subject   string
	Audience  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Issuer is the workload issuer for the service's ISSUER.
func Issuer(issuer string) string { return strings.TrimRight(issuer, "/") + PathPrefix }

func NewService(keySet *KeySet, issuer string, ttl time.Duration, list []config.WorkloadIdentity, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	s := &Service{Keys: keySet, issuer: Issuer(issuer), ttl: ttl, now: now}
	for _, w := range list {
		s.identities = append(s.identities, identity{WorkloadIdentity: w, tokenSum: sha256.Sum256([]byte(w.Token))})
	}
	return s
}

// Issuer is iss of every token: <ISSUER>/workload.
func (s *Service) Issuer() string { return s.issuer }

// Authenticate returns the workload whose secret is secret. Every
// configured secret is compared, in constant time.
func (s *Service) Authenticate(secret string) (config.WorkloadIdentity, error) {
	got := sha256.Sum256([]byte(secret))
	found := -1
	for i, w := range s.identities {
		if subtle.ConstantTimeCompare(got[:], w.tokenSum[:]) == 1 && secret != "" {
			found = i
		}
	}
	if found < 0 {
		return config.WorkloadIdentity{}, ErrUnknownWorkload
	}
	return s.identities[found].WorkloadIdentity, nil
}

// Mint signs a token for w and audience; an empty audience means w's only
// one.
func (s *Service) Mint(ctx context.Context, w config.WorkloadIdentity, audience string) (Token, error) {
	if audience == "" && len(w.Audiences) == 1 {
		audience = w.Audiences[0]
	}
	if !slices.Contains(w.Audiences, audience) {
		return Token{}, ErrAudience
	}
	kid, priv, err := s.Keys.SigningKey()
	if err != nil {
		return Token{}, err
	}
	now := s.now().UTC().Truncate(time.Second)
	exp := now.Add(s.ttl)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   w.Subject(),
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(exp),
		ID:        ids.New(ids.TokenID),
	})
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		return Token{}, err
	}
	logger.FromCtx(ctx).Debug().Str("sub", w.Subject()).Str("aud", audience).Str("kid", kid).Msg("minted workload token")
	return Token{JWT: signed, Subject: w.Subject(), Audience: audience, IssuedAt: now, ExpiresAt: exp}, nil
}

// Run calls Keys.Ensure every interval until ctx is done.
func (s *Service) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Keys.Ensure(ctx); err != nil && ctx.Err() == nil {
				logger.FromCtx(ctx).Error().Err(err).Msg("workload key maintenance failed")
			}
		}
	}
}
