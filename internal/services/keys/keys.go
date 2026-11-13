// Package keys manages the Ed25519 signing keys: creation, scheduled
// rotation, encryption at rest and the public JWKS.
//
// Lifecycle of a key (all times stored in signing_keys):
//
//	created_at    published in JWKS from here on
//	activated_at  used for signing from here on (KEY_PUBLISH_LEAD after creation,
//	              so verifiers with a cached JWKS already know the kid)
//	retired_at    stops signing (= the next key's activated_at)
//	retired_at + max token TTL + margin   dropped from JWKS
//
// Every replica runs Ensure periodically. Creation happens inside a
// transaction holding a Postgres advisory lock, so only one replica creates
// a key; the others pick it up on their next reload.
package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
)

const (
	AlgEdDSA = "EdDSA"
	// jwksMargin is extra JWKS retention after the last token a retired key
	// signed has expired, covering clock skew and verifier caches.
	jwksMargin = 10 * time.Minute
	// reloadThrottle limits DB reloads triggered by unknown kids.
	reloadThrottle = 10 * time.Second
)

var (
	ErrNoSigningKey = errors.New("keys: no signing key available")
	ErrUnknownKey   = errors.New("keys: unknown kid")
)

// JWK is a public Ed25519 key in RFC 8037 form.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// KeyInfo describes a key for listings (never includes private material).
type KeyInfo struct {
	KID         string     `json:"kid"`
	Alg         string     `json:"alg"`
	CreatedAt   time.Time  `json:"created_at"`
	ActivatedAt time.Time  `json:"activated_at"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
	State       string     `json:"state"` // pending | active | retired | expired
}

type KeyServiceImpl interface {
	// Ensure creates the first key, schedules the next one when rotation is
	// due, and reloads the in-memory key set.
	Ensure(ctx context.Context) error
	// Rotate creates a new key now. immediate activates it right away instead
	// of after KEY_PUBLISH_LEAD. Returns the new kid.
	Rotate(ctx context.Context, immediate bool) (string, error)
	// SigningKey returns the key to sign with now.
	SigningKey(ctx context.Context) (kid string, priv ed25519.PrivateKey, err error)
	// PublicKey returns the verification key for kid if it is still published.
	PublicKey(ctx context.Context, kid string) (ed25519.PublicKey, error)
	JWKS(ctx context.Context) JWKS
	List(ctx context.Context) ([]KeyInfo, error)
	// Run calls Ensure every interval until ctx is done.
	Run(ctx context.Context, every time.Duration)
}

type Options struct {
	EncryptionKey []byte        // 32 bytes
	Rotation      time.Duration // KEY_ROTATION
	PublishLead   time.Duration // KEY_PUBLISH_LEAD
	MaxTokenTTL   time.Duration // longest JWT lifetime we sign
	Now           func() time.Time
}

type loadedKey struct {
	kid         string
	pub         ed25519.PublicKey
	priv        ed25519.PrivateKey
	jwk         JWK
	createdAt   time.Time
	activatedAt time.Time
	retiredAt   *time.Time
}

type KeyService struct {
	Repository signingkey.SigningKeyRepositoryImpl
	Tx         db.TxManagerImpl
	opts       Options

	mu         sync.RWMutex
	keys       []*loadedKey // usable keys, ascending activated_at
	lastReload time.Time
}

func NewKeyService(repo signingkey.SigningKeyRepositoryImpl, tx db.TxManagerImpl, opts Options) (KeyServiceImpl, error) {
	if len(opts.EncryptionKey) != 32 {
		return nil, errors.New("keys: encryption key must be 32 bytes")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &KeyService{Repository: repo, Tx: tx, opts: opts}, nil
}

func (s *KeyService) now() time.Time { return s.opts.Now().UTC() }

// jwksCutoff: keys retired before this are no longer published.
func (s *KeyService) jwksCutoff(now time.Time) time.Time {
	return now.Add(-(s.opts.MaxTokenTTL + jwksMargin))
}

func (s *KeyService) Ensure(ctx context.Context) error {
	created := ""
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.Repository.LockRotation(ctx); err != nil {
			return err
		}
		now := s.now()
		all, err := s.Repository.ListUsable(ctx, now)
		if err != nil {
			return err
		}
		current, pending := classify(all, now)
		switch {
		case current == nil && pending == nil:
			kid, err := s.create(ctx, now, now)
			created = kid
			return err
		case pending != nil:
			return nil // next key already scheduled
		}
		// Schedule the successor KEY_PUBLISH_LEAD before rotation is due.
		due := current.ActivatedAt.Add(s.opts.Rotation)
		if now.Before(due.Add(-s.opts.PublishLead)) {
			return nil
		}
		activate := due
		if earliest := now.Add(s.opts.PublishLead); activate.Before(earliest) {
			activate = earliest
		}
		kid, err := s.create(ctx, now, activate)
		if err != nil {
			return err
		}
		created = kid
		return s.Repository.Retire(ctx, current.KID, activate)
	})
	if err != nil {
		return fmt.Errorf("keys: ensure: %w", err)
	}
	if created != "" {
		logger.FromCtx(ctx).Info().Str("kid", created).Msg("created signing key")
	}
	return s.reload(ctx)
}

func (s *KeyService) Rotate(ctx context.Context, immediate bool) (string, error) {
	var kid string
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.Repository.LockRotation(ctx); err != nil {
			return err
		}
		now := s.now()
		all, err := s.Repository.ListUsable(ctx, now)
		if err != nil {
			return err
		}
		activate := now
		if !immediate {
			activate = now.Add(s.opts.PublishLead)
		}
		// Every key still signing (or scheduled to) stops when the new one starts.
		for _, k := range all {
			if k.RetiredAt == nil || k.RetiredAt.After(activate) {
				if err := s.Repository.Retire(ctx, k.KID, activate); err != nil {
					return err
				}
			}
		}
		kid, err = s.create(ctx, now, activate)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("keys: rotate: %w", err)
	}
	return kid, s.reload(ctx)
}

// classify picks the key signing at now and a scheduled future key.
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

func (s *KeyService) create(ctx context.Context, now, activate time.Time) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	kid := ids.New(ids.SigningKey)
	enc, err := keycrypt.Seal(s.opts.EncryptionKey, priv.Seed(), []byte(kid))
	if err != nil {
		return "", err
	}
	jwk := publicJWK(kid, pub)
	return kid, s.Repository.Create(ctx, &signingkey.SigningKey{
		KID:           kid,
		Alg:           AlgEdDSA,
		PrivateKeyEnc: enc,
		PublicJWK: repositories.JSONB{
			"kty": jwk.Kty, "crv": jwk.Crv, "x": jwk.X, "kid": jwk.Kid, "alg": jwk.Alg, "use": jwk.Use,
		},
		CreatedAt:   now,
		ActivatedAt: activate,
	})
}

func publicJWK(kid string, pub ed25519.PublicKey) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub), Kid: kid, Alg: AlgEdDSA, Use: "sig"}
}

func (s *KeyService) reload(ctx context.Context) error {
	now := s.now()
	rows, err := s.Repository.ListUsable(ctx, s.jwksCutoff(now))
	if err != nil {
		return fmt.Errorf("keys: reload: %w", err)
	}
	loaded := make([]*loadedKey, 0, len(rows))
	for _, r := range rows {
		seed, err := keycrypt.Open(s.opts.EncryptionKey, r.PrivateKeyEnc, []byte(r.KID))
		if err != nil {
			return fmt.Errorf("keys: %s: %w", r.KID, err)
		}
		if len(seed) != ed25519.SeedSize {
			return fmt.Errorf("keys: %s: bad seed length", r.KID)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		loaded = append(loaded, &loadedKey{
			kid: r.KID, pub: pub, priv: priv, jwk: publicJWK(r.KID, pub),
			createdAt: r.CreatedAt, activatedAt: r.ActivatedAt, retiredAt: r.RetiredAt,
		})
	}
	s.mu.Lock()
	s.keys = loaded
	s.lastReload = now
	s.mu.Unlock()
	return nil
}

func (s *KeyService) SigningKey(ctx context.Context) (string, ed25519.PrivateKey, error) {
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
		best = pending // only if every active key was retired early
	}
	if best == nil {
		return "", nil, ErrNoSigningKey
	}
	return best.kid, best.priv, nil
}

func (s *KeyService) lookup(kid string, now time.Time) (*loadedKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := s.jwksCutoff(now)
	for _, k := range s.keys {
		if k.kid == kid {
			if k.retiredAt != nil && !k.retiredAt.After(cutoff) {
				return nil, false
			}
			return k, true
		}
	}
	return nil, false
}

func (s *KeyService) PublicKey(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	now := s.now()
	if k, ok := s.lookup(kid, now); ok {
		return k.pub, nil
	}
	// Another replica may have created a key we haven't loaded yet.
	s.mu.RLock()
	stale := now.Sub(s.lastReload) > reloadThrottle
	s.mu.RUnlock()
	if stale {
		if err := s.reload(ctx); err != nil {
			return nil, err
		}
		if k, ok := s.lookup(kid, now); ok {
			return k.pub, nil
		}
	}
	return nil, ErrUnknownKey
}

func (s *KeyService) JWKS(ctx context.Context) JWKS {
	now := s.now()
	cutoff := s.jwksCutoff(now)
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

func (s *KeyService) List(ctx context.Context) ([]KeyInfo, error) {
	rows, err := s.Repository.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	cutoff := s.jwksCutoff(now)
	out := make([]KeyInfo, 0, len(rows))
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
		out = append(out, KeyInfo{KID: r.KID, Alg: r.Alg, CreatedAt: r.CreatedAt, ActivatedAt: r.ActivatedAt, RetiredAt: r.RetiredAt, State: state})
	}
	slices.SortFunc(out, func(a, b KeyInfo) int { return a.ActivatedAt.Compare(b.ActivatedAt) })
	return out, nil
}

func (s *KeyService) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Ensure(ctx); err != nil && ctx.Err() == nil {
				logger.FromCtx(ctx).Error().Err(err).Msg("signing key maintenance failed")
			}
		}
	}
}
