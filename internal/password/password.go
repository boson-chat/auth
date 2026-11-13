// Package password hashes passwords with argon2id into PHC strings and
// enforces the password policy.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MinLength = 10
	MaxLength = 256
	saltLen   = 16
	keyLen    = 32
)

var (
	ErrTooShort        = fmt.Errorf("password must be at least %d characters", MinLength)
	ErrTooLong         = fmt.Errorf("password must be at most %d characters", MaxLength)
	ErrMatchesIdentity = errors.New("password must not be your username or email")
	ErrInvalidHash     = errors.New("password: invalid hash format")
)

// Params are argon2id cost parameters.
type Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

// DefaultParams: 64 MiB, 3 passes, 2 lanes.
var DefaultParams = Params{MemoryKiB: 64 * 1024, Iterations: 3, Parallelism: 2}

// Hasher hashes and verifies passwords.
type Hasher struct {
	params Params
	dummy  string
}

// NewHasher returns a Hasher using p for new hashes.
func NewHasher(p Params) (*Hasher, error) {
	if p.MemoryKiB < 8*uint32(p.Parallelism) || p.Iterations < 1 || p.Parallelism < 1 {
		return nil, fmt.Errorf("password: invalid argon2 params %+v", p)
	}
	h := &Hasher{params: p}
	pw := make([]byte, 16)
	_, _ = rand.Read(pw)
	d, err := h.Hash(base64.RawStdEncoding.EncodeToString(pw))
	if err != nil {
		return nil, err
	}
	h.dummy = d
	return h, nil
}

// Hash returns a PHC string: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>.
func (h *Hasher) Hash(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	p := h.params
	key := argon2.IDKey([]byte(pw), salt, p.Iterations, p.MemoryKiB, p.Parallelism, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether pw matches the PHC string, and whether the hash
// should be replaced because it uses different parameters than h.
func (h *Hasher) Verify(pw, phc string) (ok, needsRehash bool, err error) {
	p, salt, want, err := decode(phc)
	if err != nil {
		return false, false, err
	}
	got := argon2.IDKey([]byte(pw), salt, p.Iterations, p.MemoryKiB, p.Parallelism, uint32(len(want)))
	ok = subtle.ConstantTimeCompare(got, want) == 1
	return ok, ok && p != h.params, nil
}

// VerifyDummy burns the same time as a real Verify. Call it when the account
// does not exist so response timing does not reveal that.
func (h *Hasher) VerifyDummy(pw string) {
	_, _, _ = h.Verify(pw, h.dummy)
}

func decode(phc string) (Params, []byte, []byte, error) {
	parts := strings.Split(phc, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrInvalidHash
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return Params{}, nil, nil, ErrInvalidHash
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Iterations, &p.Parallelism); err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	if p.Iterations < 1 || p.Parallelism < 1 || p.MemoryKiB < 8*uint32(p.Parallelism) || p.MemoryKiB > 4*1024*1024 {
		return Params{}, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return Params{}, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 {
		return Params{}, nil, nil, ErrInvalidHash
	}
	return p, salt, key, nil
}

// CheckPolicy enforces length (in characters) and rejects a password equal
// to the username or email, ignoring case.
func CheckPolicy(pw, username, email string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinLength {
		return ErrTooShort
	}
	if n > MaxLength {
		return ErrTooLong
	}
	if (username != "" && strings.EqualFold(pw, username)) || (email != "" && strings.EqualFold(pw, email)) {
		return ErrMatchesIdentity
	}
	return nil
}
