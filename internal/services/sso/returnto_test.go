package sso

import (
	"testing"
	"time"
)

func TestReturnToPolicy(t *testing.T) {
	p, err := NewReturnToPolicy("https://app.example.com",
		[]string{"https://app.example.com", "https://auth.example.com", "https://admin.example.com"},
		[]string{"http://127.0.0.1:*", "http://[::1]:*", "boson://", "https://partner.example.org/sso/"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		in, mode, want, wantMode string
	}{
		{"", "", "https://app.example.com/", ModeCookie},
		{"/chat?x=1#top", "", "https://app.example.com/chat?x=1#top", ModeCookie},
		{"https://admin.example.com/users", "", "https://admin.example.com/users", ModeCookie},
		{"https://app.example.com/", "code", "https://app.example.com/", ModeCode},
		{"http://127.0.0.1:53682/cb", "", "http://127.0.0.1:53682/cb", ModeCode},
		{"http://[::1]:8000/", "", "http://[::1]:8000/", ModeCode},
		{"boson://sso/callback", "", "boson://sso/callback", ModeCode},
		{"BOSON://x", "", "boson://x", ModeCode},
		{"https://partner.example.org/sso/done", "", "https://partner.example.org/sso/done", ModeCode},
	} {
		got, mode, err := p.Resolve(tc.in, tc.mode)
		if err != nil || got != tc.want || mode != tc.wantMode {
			t.Errorf("Resolve(%q, %q) = %q, %q, %v; want %q, %q", tc.in, tc.mode, got, mode, err, tc.want, tc.wantMode)
		}
	}
	for _, tc := range []struct{ in, mode string }{
		{"https://evil.example/", ""},
		{"//evil.example/", ""},
		{"/\\evil.example", ""},
		{"https://app.example.com.evil.example/", ""},
		{"https://app.example.com:8443/", ""},
		{"http://app.example.com/", ""},
		{"https://user:pw@app.example.com/", ""},
		{"javascript:alert(1)", ""},
		{"http://localhost:5000/", ""},
		{"http://127.0.0.2:5000/", ""},
		{"https://partner.example.org/other", ""},
		{"evil://x", ""},
		{"http://127.0.0.1:5000/", ModeCookie},
		{"/", "token"},
		{"https://app.example.com/\r\nSet-Cookie: x", ""},
	} {
		if got, _, err := p.Resolve(tc.in, tc.mode); err == nil {
			t.Errorf("Resolve(%q, %q) = %q, want an error", tc.in, tc.mode, got)
		}
	}
	if _, err := NewReturnToPolicy("https://app.example.com", nil, []string{"https://"}); err == nil {
		t.Error("pattern without host accepted")
	}
	if _, err := NewReturnToPolicy("https://app.example.com", nil, []string{"no-scheme"}); err == nil {
		t.Error("pattern without scheme accepted")
	}
}

func TestWithParams(t *testing.T) {
	if got := WithParams("boson://sso/cb?a=1#f", "code", "bsc_x y"); got != "boson://sso/cb?a=1&code=bsc_x+y#f" {
		t.Fatalf("WithParams = %q", got)
	}
}

func TestStateCookie(t *testing.T) {
	key, err := stateKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	fs := flowState{Slug: "g", State: "st", Saved: map[string]string{"nonce": "n"}, ReturnTo: "https://a/", Mode: ModeCode, Exp: now.Add(time.Minute).Unix()}
	c, err := sealState(key, fs)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openState(key, c, now)
	if err != nil || got.Slug != "g" || got.Saved["nonce"] != "n" || got.Mode != ModeCode {
		t.Fatalf("open: %+v %v", got, err)
	}
	if _, err := openState(key, c, now.Add(2*time.Minute)); err == nil {
		t.Error("expired state accepted")
	}
	other, _ := stateKey(append(make([]byte, 31), 1))
	if _, err := openState(other, c, now); err == nil {
		t.Error("state sealed with another key accepted")
	}
	b := []byte(c)
	b[len(b)/2] ^= 1
	if _, err := openState(key, string(b), now); err == nil {
		t.Error("tampered state accepted")
	}
	if _, err := openState(key, "", now); err == nil {
		t.Error("empty state accepted")
	}
}
