// Package textutil guards values on their way into Postgres text columns,
// which reject invalid UTF-8 and NUL bytes.
package textutil

import (
	"strings"
	"unicode/utf8"
)

// Storable reports whether s can be stored in or compared against a text column.
func Storable(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

// Clean makes untrusted header values storable: invalid sequences become
// U+FFFD, NULs are dropped, and the result is cut to at most maxBytes on a
// rune boundary.
func Clean(s string, maxBytes int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
