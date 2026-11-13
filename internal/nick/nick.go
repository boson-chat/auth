// Package nick validates usernames, which double as IRC nicknames and voice
// display identities, and folds them with RFC 1459 casemapping.
package nick

import (
	"errors"
	"strings"
)

const MaxLen = 30

var (
	ErrEmpty    = errors.New("username is required")
	ErrTooLong  = errors.New("username must be at most 30 characters")
	ErrBadFirst = errors.New("username must start with a letter or one of []\\`_^{|}")
	ErrBadChar  = errors.New("username may only contain letters, digits and -[]\\`_^{|}")
	ErrReserved = errors.New("username is reserved")
)

// reserved holds folded names that would let a user impersonate services.
var reserved = map[string]struct{}{}

func init() {
	for _, n := range []string{
		"nickserv", "chanserv", "memoserv", "operserv", "hostserv", "botserv",
		"global", "services", "statserv", "helpserv", "saslserv", "irc", "server", "root",
	} {
		reserved[Fold(n)] = struct{}{}
	}
}

func isLetter(c byte) bool  { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isSpecial(c byte) bool { return strings.IndexByte("[]\\`_^{|}", c) >= 0 }

// Validate checks IRC nickname rules: 1–30 chars, first a letter or one of
// []\`_^{|}, then letters, digits or -[]\`_^{|}. ASCII only.
func Validate(s string) error {
	if s == "" {
		return ErrEmpty
	}
	if len(s) > MaxLen {
		return ErrTooLong
	}
	if c := s[0]; !isLetter(c) && !isSpecial(c) {
		return ErrBadFirst
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isLetter(c) && !isDigit(c) && !isSpecial(c) && c != '-' {
			return ErrBadChar
		}
	}
	if _, ok := reserved[Fold(s)]; ok {
		return ErrReserved
	}
	return nil
}

// Fold maps s to its RFC 1459 canonical form: ASCII lower case plus
// [ ] \ ~ → { } | ^. Two nicks collide on IRC exactly when their folds match.
func Fold(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			b[i] = c + ('a' - 'A')
		case c == '[':
			b[i] = '{'
		case c == ']':
			b[i] = '}'
		case c == '\\':
			b[i] = '|'
		case c == '~':
			b[i] = '^'
		}
	}
	return string(b)
}
