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

// Sanitize turns an arbitrary name (an SSO claim, an email local part) into
// a valid nickname, or "" if nothing usable is left: separators become _,
// other invalid characters are dropped, a leading digit or - gets a "u"
// prefix, and the result is cut to MaxLen. Reserved names get a trailing _.
func Sanitize(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isLetter(c) || isDigit(c) || isSpecial(c) || c == '-':
			b = append(b, c)
		case c == '.' || c == ' ' || c == '+' || c == '@':
			if len(b) > 0 && b[len(b)-1] != '_' {
				b = append(b, '_')
			}
		}
	}
	out := strings.Trim(string(b), "_-")
	if out == "" {
		return ""
	}
	if c := out[0]; !isLetter(c) && !isSpecial(c) {
		out = "u" + out
	}
	if len(out) > MaxLen {
		out = strings.TrimRight(out[:MaxLen], "_-")
	}
	if _, ok := reserved[Fold(out)]; ok {
		if len(out) == MaxLen {
			out = out[:MaxLen-1]
		}
		out += "_"
	}
	if Validate(out) != nil {
		return ""
	}
	return out
}
