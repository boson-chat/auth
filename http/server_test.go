package http

import "testing"

func TestOriginOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://auth.example.com":        "https://auth.example.com",
		"https://auth.example.com/":       "https://auth.example.com",
		"http://localhost:8080/base/path": "http://localhost:8080",
		"auth.example.com":                "",
		"":                                "",
		"://bad":                          "",
	} {
		if got := originOf(in); got != want {
			t.Errorf("originOf(%q) = %q, want %q", in, got, want)
		}
	}
}
