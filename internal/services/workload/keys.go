package workload

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/signingkey"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/keycrypt"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/services/keys"
)

// AlgES256 is the only algorithm of the workload issuer (Google Workload
// Identity Federation accepts RS256 and ES256, not EdDSA).
const AlgES256 = "ES256"

// jwksMargin is extra JWKS retention after the last token a retired key
// signed has expired, covering clock skew and verifier caches.
const jwksMargin = 10 * time.Minute

var ErrNoSigningKey = errors.New("workload: no signing key available")

// JWK is a public P-256 key (RFC 7518 §6.2).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// JWKS is the workload issuer's key set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// KeyOptions configure the workload key set.
type KeyOptions struct {
	EncryptionKey []byte        // AUTH_KEY_ENCRYPTION_KEY, 32 bytes
	Rotation      time.Duration // WORKLOAD_KEY_ROTATION
	PublishLead   time.Duration // WORKLOAD_KEY_PUBLISH_LEAD
	TokenTTL      time.Duration // WORKLOAD_TOKEN_TTL
	Now           func() time.Time
}

type loadedKey struct {
	kid         string
	priv        *ecdsa.PrivateKey
	jwk         JWK
	activatedAt time.Time
	retiredAt   *time.Time
}

// KeySet manages the ES256 keys in workload_signing_keys. Lifecycle as in
// package keys: published from created_at, signs from activated_at
// (PublishLead later), retired when the successor activates and dropped
// from the JWKS once its last token expired plus PublishLead and a margin.
type KeySet struct {
	repo signingkey.SigningKeyRepositoryImpl
	tx   db.TxManagerImpl
	opts KeyOptions

	mu   sync.RWMutex
	keys []*loadedKey // ascending activated_at
}

func NewKeySet(repo signingkey.SigningKeyRepositoryImpl, tx db.TxManagerImpl, opts KeyOptions) (*KeySet, error) {
	if len(opts.EncryptionKey) != 32 {
		return nil, errors.New("workload: encryption key must be 32 bytes")
	}
	if opts.Rotation <= 0 {
		return nil, errors.New("workload: rotation must be positive")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &KeySet{repo: repo, tx: tx, opts: opts}, nil
}

func (s *KeySet) now() time.Time { return s.opts.Now().UTC() }

// jwksCutoff: keys retired before this are no longer published.
func (s *KeySet) jwksCutoff(now time.Time) time.Time {
	return now.Add(-(s.opts.TokenTTL + s.opts.PublishLead + jwksMargin))
}

// Ensure creates the first key, schedules the successor PublishLead before
// rotation is due and reloads the key set. Safe on every replica.
func (s *KeySet) Ensure(ctx context.Context) error {
	created := ""
	err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.LockRotation(ctx); err != nil {
			return err
		}
		now := s.now()
		all, err := s.repo.ListUsable(ctx, now)
		if err != nil {
			return err
		}
		current, pending := classify(all, now)
		switch {
		case current == nil && pending == nil:
			created, err = s.create(ctx, now, now)
			return err
		case pending != nil:
			return nil
		}
		due := current.ActivatedAt.Add(s.opts.Rotation)
		if now.Before(due.Add(-s.opts.PublishLead)) {
			return nil
		}
		activate := due
		if earliest := now.Add(s.opts.PublishLead); activate.Before(earliest) {
			activate = earliest
		}
		if created, err = s.create(ctx, now, activate); err != nil {
			return err
		}
		return s.repo.Retire(ctx, current.KID, activate)
	})
	if err != nil {
		return fmt.Errorf("workload keys: ensure: %w", err)
	}
	if created != "" {
		logger.FromCtx(ctx).Info().Str("kid", created).Msg("created workload signing key")
	}
	return s.reload(ctx)
}

// Rotate creates a new key now; immediate signs with it right away
// instead of after PublishLead. Returns the new kid.
func (s *KeySet) Rotate(ctx context.Context, immediate bool) (string, error) {
	var kid string
	err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.LockRotation(ctx); err != nil {
			return err
		}
		now := s.now()
		all, err := s.repo.ListUsable(ctx, now)
		if err != nil {
			return err
		}
		activate := now
		if !immediate {
			activate = now.Add(s.opts.PublishLead)
		}
		for _, k := range all {
			if k.RetiredAt == nil || k.RetiredAt.After(activate) {
				if err := s.repo.Retire(ctx, k.KID, activate); err != nil {
					return err
				}
			}
		}
		kid, err = s.create(ctx, now, activate)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("workload keys: rotate: %w", err)
	}
	return kid, s.reload(ctx)
}

func classify(all []*signingkey.SigningKey, now time.Time) (current, pending *signingkey.SigningKey) {
	for _, k := range all {
		if k.ActivatedAt.After(now) {
			if pending == nil || k.ActivatedAt.Before(pending.ActivatedAt) {
				pending = k
			}
			continue
		}
		if k.RetiredAt != nil && !k.RetiredAt.After(now) {
			continue
		}
		if current == nil || k.ActivatedAt.After(current.ActivatedAt) {
			current = k
		}
	}
	return current, pending
}

func (s *KeySet) create(ctx context.Context, now, activate time.Time) (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	kid := ids.New(ids.WorkloadKey)
	enc, err := keycrypt.Seal(s.opts.EncryptionKey, der, []byte(kid))
	if err != nil {
		return "", err
	}
	jwk := publicJWK(kid, &priv.PublicKey)
	return kid, s.repo.Create(ctx, &signingkey.SigningKey{
		KID: kid, Alg: AlgES256, PrivateKeyEnc: enc,
		PublicJWK: repositories.JSONB{
			"kty": jwk.Kty, "crv": jwk.Crv, "x": jwk.X, "y": jwk.Y, "kid": jwk.Kid, "alg": jwk.Alg, "use": jwk.Use,
		},
		CreatedAt: now, ActivatedAt: activate,
	})
}

func publicJWK(kid string, pub *ecdsa.PublicKey) JWK {
	// Uncompressed point 0x04 || X || Y, each coordinate 32 bytes.
	b, _ := pub.Bytes()
	enc := base64.RawURLEncoding.EncodeToString
	return JWK{Kty: "EC", Crv: "P-256", X: enc(b[1:33]), Y: enc(b[33:65]), Kid: kid, Alg: AlgES256, Use: "sig"}
}

func (s *KeySet) reload(ctx context.Context) error {
	rows, err := s.repo.ListUsable(ctx, s.jwksCutoff(s.now()))
	if err != nil {
		return fmt.Errorf("workload keys: reload: %w", err)
	}
	loaded := make([]*loadedKey, 0, len(rows))
	for _, r := range rows {
		der, err := keycrypt.Open(s.opts.EncryptionKey, r.PrivateKeyEnc, []byte(r.KID))
		if err != nil {
			return fmt.Errorf("workload keys: %s: %w", r.KID, err)
		}
		k, err := x509.ParsePKCS8PrivateKey(der)
		priv, ok := k.(*ecdsa.PrivateKey)
		if err != nil || !ok || priv.Curve != elliptic.P256() {
			return fmt.Errorf("workload keys: %s: not a P-256 key", r.KID)
		}
		loaded = append(loaded, &loadedKey{
			kid: r.KID, priv: priv, jwk: publicJWK(r.KID, &priv.PublicKey),
			activatedAt: r.ActivatedAt, retiredAt: r.RetiredAt,
		})
	}
	s.mu.Lock()
	s.keys = loaded
	s.mu.Unlock()
	return nil
}

// SigningKey returns the key to sign with now.
func (s *KeySet) SigningKey() (string, *ecdsa.PrivateKey, error) {
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best, pending *loadedKey
	for _, k := range s.keys {
		if k.activatedAt.After(now) {
			if pending == nil || k.activatedAt.Before(pending.activatedAt) {
				pending = k
			}
			continue
		}
		if k.retiredAt != nil && !k.retiredAt.After(now) {
			continue
		}
		if best == nil || k.activatedAt.After(best.activatedAt) {
			best = k
		}
	}
	if best == nil {
		best = pending
	}
	if best == nil {
		return "", nil, ErrNoSigningKey
	}
	return best.kid, best.priv, nil
}

// JWKS is the published key set: pending, active and recently retired keys.
func (s *KeySet) JWKS() JWKS {
	cutoff := s.jwksCutoff(s.now())
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := JWKS{Keys: make([]JWK, 0, len(s.keys))}
	for _, k := range s.keys {
		if k.retiredAt != nil && !k.retiredAt.After(cutoff) {
			continue
		}
		out.Keys = append(out.Keys, k.jwk)
	}
	return out
}

// List describes every workload key (never private material).
func (s *KeySet) List(ctx context.Context) ([]keys.KeyInfo, error) {
	rows, err := s.repo.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	cutoff := s.jwksCutoff(now)
	out := make([]keys.KeyInfo, 0, len(rows))
	for _, r := range rows {
		state := "active"
		switch {
		case r.ActivatedAt.After(now):
			state = "pending"
		case r.RetiredAt != nil && !r.RetiredAt.After(cutoff):
			state = "expired"
		case r.RetiredAt != nil && !r.RetiredAt.After(now):
			state = "retired"
		}
		out = append(out, keys.KeyInfo{KID: r.KID, Alg: r.Alg, CreatedAt: r.CreatedAt, ActivatedAt: r.ActivatedAt, RetiredAt: r.RetiredAt, State: state})
	}
	slices.SortFunc(out, func(a, b keys.KeyInfo) int { return a.ActivatedAt.Compare(b.ActivatedAt) })
	return out, nil
}
