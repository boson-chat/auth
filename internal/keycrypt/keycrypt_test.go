package keycrypt

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSealOpen(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	msg := []byte("ed25519 seed bytes")
	sealed, err := Seal(key, msg, []byte("key_1"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, sealed, []byte("key_1"))
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if _, err := Open(key, sealed, []byte("key_2")); err == nil {
		t.Fatal("ciphertext must be bound to its aad")
	}
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	if _, err := Open(other, sealed, []byte("key_1")); err == nil {
		t.Fatal("wrong key must fail")
	}
	if _, err := Seal(key[:16], msg, nil); err == nil {
		t.Fatal("short key must be rejected")
	}
}
