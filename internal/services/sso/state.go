package sso

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/boson-chat/auth/internal/keycrypt"
)

// flowState is everything a login flow must remember between /start and
// the callback. It travels in an encrypted, HttpOnly cookie, so the server
// keeps no per-flow state and any replica can finish the flow.
type flowState struct {
	Slug      string            `json:"s"`
	State     string            `json:"st"`
	Saved     map[string]string `json:"sv,omitempty"`
	ReturnTo  string            `json:"r"`
	Mode      string            `json:"m"`
	Invite    string            `json:"i,omitempty"`
	Challenge string            `json:"c,omitempty"`
	Exp       int64             `json:"e"`
}

const stateAAD = "boson-sso-state-v1"

var errBadState = errors.New("sso: state cookie invalid or expired")

// stateKey derives the cookie key from AUTH_KEY_ENCRYPTION_KEY, so the KEK
// itself never encrypts attacker-visible data.
func stateKey(kek []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, kek, nil, stateAAD, 32)
}

func sealState(key []byte, fs flowState) (string, error) {
	b, err := json.Marshal(fs)
	if err != nil {
		return "", err
	}
	ct, err := keycrypt.Seal(key, b, []byte(stateAAD))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

func openState(key []byte, cookie string, now time.Time) (flowState, error) {
	var fs flowState
	if cookie == "" || len(cookie) > 8192 {
		return fs, errBadState
	}
	ct, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil {
		return fs, errBadState
	}
	b, err := keycrypt.Open(key, ct, []byte(stateAAD))
	if err != nil {
		return fs, errBadState
	}
	if err := json.Unmarshal(b, &fs); err != nil || fs.State == "" || now.Unix() > fs.Exp {
		return flowState{}, errBadState
	}
	return fs, nil
}
