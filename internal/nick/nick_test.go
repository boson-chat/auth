package nick

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	valid := []string{"a", "alice", "Alice-2", "[bot]", "`x", "_", "^^", "{x}|y", "a" + strings.Repeat("b", 29), "x-"}
	for _, s := range valid {
		if err := Validate(s); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", s, err)
		}
	}
	invalid := map[string]error{
		"":                      ErrEmpty,
		strings.Repeat("a", 31): ErrTooLong,
		"1abc":                  ErrBadFirst,
		"-abc":                  ErrBadFirst,
		"al ice":                ErrBadChar,
		"al.ice":                ErrBadChar,
		"al@ice":                ErrBadChar,
		"alice~":                ErrBadChar,
		"ålice":                 ErrBadFirst,
		"aé":                    ErrBadChar,
		"NickServ":              ErrReserved,
		"CHANSERV":              ErrReserved,
	}
	for s, want := range invalid {
		if err := Validate(s); err != want {
			t.Errorf("Validate(%q) = %v, want %v", s, err, want)
		}
	}
}

func TestFold(t *testing.T) {
	cases := map[string]string{
		"Alice":    "alice",
		"[Foo]":    "{foo}",
		`a\b`:      "a|b",
		"x~":       "x^",
		"{foo}|^":  "{foo}|^",
		"ABC-123_": "abc-123_",
	}
	for in, want := range cases {
		if got := Fold(in); got != want {
			t.Errorf("Fold(%q) = %q, want %q", in, got, want)
		}
	}
	if Fold("[Bot]") != Fold("{bot}") {
		t.Error("[Bot] and {bot} must collide")
	}
}
