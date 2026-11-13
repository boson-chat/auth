package textutil

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClean(t *testing.T) {
	if got := Clean("ok\x00\xffua", 100); got != "ok�ua" {
		t.Fatalf("Clean = %q", got)
	}
	s := strings.Repeat("é", 300) // 600 bytes
	got := Clean(s, 511)
	if !utf8.ValidString(got) || len(got) > 511 || len(got) != 510 {
		t.Fatalf("cut mid-rune: len=%d valid=%v", len(got), utf8.ValidString(got))
	}
	if Storable("a\x00") || Storable("\xff") || !Storable("héllo") {
		t.Fatal("Storable")
	}
}
