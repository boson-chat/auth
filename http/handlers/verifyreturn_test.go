package handlers

import (
	"testing"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/services/sso"
)

func verifyHandlers(t *testing.T, webClient string) *Handlers {
	t.Helper()
	p, err := sso.NewReturnToPolicy("https://auth.example.com",
		[]string{"https://auth.example.com", "https://chat.example.com"},
		[]string{"http://127.0.0.1:*", "boson://"})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handlers{ReturnTo: p}
	h.Config.HTTPConfig = config.HTTPConfig{WebClientURL: webClient}
	return h
}

func TestVerifyReturnTo(t *testing.T) {
	h := verifyHandlers(t, "")
	for in, want := range map[string]string{
		"https://chat.example.com/":          "https://chat.example.com/",
		" https://chat.example.com/#/s/x ":   "https://chat.example.com/#/s/x",
		"https://CHAT.example.com/c?x=1":     "https://CHAT.example.com/c?x=1",
		"/welcome":                           "https://auth.example.com/welcome",
		"boson://verified":                   "boson://verified",
		"http://127.0.0.1:4711/cb":           "http://127.0.0.1:4711/cb",
		"":                                   "",
		"https://evil.example.com/":          "",
		"https://chat.example.com.evil.com/": "",
		"https://chat.example.com:8443/":     "",
		"http://chat.example.com/":           "",
		"//evil.example.com/":                "",
		"/\\evil.example.com":                "",
		"javascript:alert(1)":                "",
		"data:text/html,hi":                  "",
		"boson:alert":                        "",
		"https://user@chat.example.com/":     "",
		"https://chat.example.com/\r\nx":     "",
		"chat.example.com":                   "",
	} {
		if got := h.verifyReturnTo(in); got != want {
			t.Errorf("verifyReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
	if got := (&Handlers{}).verifyReturnTo("https://chat.example.com/"); got != "" {
		t.Fatalf("no policy: %q", got)
	}
}

func TestVerifiedRedirect(t *testing.T) {
	h := verifyHandlers(t, "https://chat.example.com/")
	if got := h.verifiedRedirect("boson://verified"); got != "boson://verified" {
		t.Fatalf("return_to wins: %q", got)
	}
	for _, in := range []string{"", "https://evil.example.com/", "javascript:alert(1)"} {
		if got := h.verifiedRedirect(in); got != "https://chat.example.com/" {
			t.Fatalf("%q: web client fallback, got %q", in, got)
		}
	}
	if got := verifyHandlers(t, "").verifiedRedirect("https://evil.example.com/"); got != "" {
		t.Fatalf("no fallback: %q", got)
	}
}
