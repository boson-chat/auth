package handlers

import (
	"context"
	"encoding/json"
	nethttp "net/http"
	"testing"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/services/settings"
)

type stubSettings struct{ settings.SettingsServiceImpl }

func (stubSettings) Get(context.Context) (settings.Settings, error) { return settings.Settings{}, nil }

func publicConfigBody(t *testing.T, h *Handlers) map[string]any {
	t.Helper()
	h.Settings = stubSettings{}
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
