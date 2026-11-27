package handlers

import (
	"context"
	"encoding/json"
	nethttp "net/http"
	"testing"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/services/nsaccount"
	"github.com/boson-chat/auth/internal/services/settings"
)

type stubSettings struct {
	settings.SettingsServiceImpl
	st settings.Settings
}

func (s stubSettings) Get(context.Context) (settings.Settings, error) { return s.st, nil }

func publicConfigBody(t *testing.T, h *Handlers) map[string]any {
	t.Helper()
	if h.Settings == nil {
		h.Settings = stubSettings{}
	}
	mux := nethttp.NewServeMux()
	mux.HandleFunc("GET /v1/config", h.publicConfig)
	w := get(mux, "GET", "/v1/config")
	if w.Code != nethttp.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestPublicConfigNetworkName(t *testing.T) {
	cfg := func(name string) config.Config {
		var c config.Config
		c.AppConfig.SiteName = name
		return c
	}
	for _, tc := range []struct {
		name string
		h    *Handlers
		want any
	}{
		{"env name", &Handlers{Config: cfg("IRCForever")}, "IRCForever"},
		{"built-in default is unset", &Handlers{Config: cfg(config.DefaultSiteName)}, nil},
		{"empty", &Handlers{Config: cfg("")}, nil},
		{"live name wins", &Handlers{Config: cfg("Old"), NetworkName: func() string { return "New" }}, "New"},
		{"live unset", &Handlers{Config: cfg("Old"), NetworkName: func() string { return "" }}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := publicConfigBody(t, tc.h)
			got, ok := body["network_name"]
			if !ok {
				t.Fatalf("network_name missing (want present, null when unset): %v", body)
			}
			if got != tc.want {
				t.Fatalf("network_name = %v, want %v", got, tc.want)
			}
		})
	}
}

type stubNickServ struct {
	nsaccount.NickServAccountServiceImpl
	available bool
}

func (s stubNickServ) Signup() nsaccount.SignupInfo {
	return nsaccount.SignupInfo{Available: s.available}
}

// accounts.signup follows the registration setting: false while closed
// (POST /v1/register refuses), true for open and invite-only (clients tell
// invite-only apart by registration).
func TestPublicConfigSignupFollowsRegistration(t *testing.T) {
	for _, tc := range []struct {
		name         string
		registration string
		nickserv     *stubNickServ
		want         bool
	}{
		{"local open", config.RegistrationOpen, nil, true},
		{"local invite", config.RegistrationInvite, nil, true},
		{"local closed", config.RegistrationClosed, nil, false},
		{"nickserv open", config.RegistrationOpen, &stubNickServ{available: true}, true},
		{"nickserv invite", config.RegistrationInvite, &stubNickServ{available: true}, true},
		{"nickserv closed", config.RegistrationClosed, &stubNickServ{available: true}, false},
		{"nickserv unavailable", config.RegistrationOpen, &stubNickServ{available: false}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{Settings: stubSettings{st: settings.Settings{Registration: tc.registration}}}
			if tc.nickserv != nil {
				h.NickServ = *tc.nickserv
			}
			body := publicConfigBody(t, h)
			if body["registration"] != tc.registration {
				t.Fatalf("registration = %v, want %q", body["registration"], tc.registration)
			}
			acc, ok := body["accounts"].(map[string]any)
			if !ok {
				t.Fatalf("accounts missing: %v", body)
			}
			if acc["signup"] != tc.want {
				t.Fatalf("accounts.signup = %v, want %v", acc["signup"], tc.want)
			}
		})
	}
}

// email.configured, the effective require_email_verification and
// accounts.password_reset follow the mail server.
func TestPublicConfigEmail(t *testing.T) {
	for _, tc := range []struct {
		name       string
		st         settings.Settings
		nickserv   bool
		wantVerify bool
		wantReset  bool
	}{
		{"mail server", settings.Settings{EmailConfigured: true, RequireEmailVerification: true, RequireEmailVerificationEffective: true}, false, true, true},
		{"no mail server", settings.Settings{RequireEmailVerification: true}, false, false, false},
		{"nickserv", settings.Settings{RequireEmailVerification: true, RequireEmailVerificationEffective: true}, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{Settings: stubSettings{st: tc.st}}
			if tc.nickserv {
				h.NickServ = stubNickServ{}
			}
			body := publicConfigBody(t, h)
			if got := body["email"].(map[string]any)["configured"]; got != tc.st.EmailConfigured {
				t.Fatalf("email.configured = %v", got)
			}
			if body["require_email_verification"] != tc.wantVerify {
				t.Fatalf("require_email_verification = %v, want %v", body["require_email_verification"], tc.wantVerify)
			}
			if got := body["accounts"].(map[string]any)["password_reset"]; got != tc.wantReset {
				t.Fatalf("password_reset = %v, want %v", got, tc.wantReset)
			}
		})
	}
}
