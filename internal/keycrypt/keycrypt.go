// Package keycrypt encrypts signing keys at rest with AES-256-GCM.
package keycrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

var ErrDecrypt = errors.New("keycrypt: decryption failed (wrong AUTH_KEY_ENCRYPTION_KEY?)")

// Seal encrypts plaintext with a 32-byte key. aad is authenticated but not
// stored (we bind the ciphertext to its kid). Output: nonce || ciphertext.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Open reverses Seal.
func Open(key, sealed, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrDecrypt
	}
	n := gcm.NonceSize()
	out, err := gcm.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("keycrypt: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
