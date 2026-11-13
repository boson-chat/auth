// Package opaque makes random bearer secrets (refresh tokens, email tokens,
// invite codes) and the SHA-256 digests we store instead of them.
package opaque

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// New returns prefix + 256 random bits, base64url.
func New(prefix string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// Hash is the stored form of a token.
func Hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
