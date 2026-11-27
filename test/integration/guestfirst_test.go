package integration

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
)

func TestGuestFirstSetting(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.AccountConfig.SettingsCacheTTL = 0 })
	adminAT := e.adminToken("netadmin")
	cfg := e.api("GET", "/v1/config", nil)
	if cfg.body["guest_first"] != false || cfg.body["guest_first_channel"] != nil {
		t.Fatalf("defaults: %s", cfg.raw)
	}

	r := e.api("PATCH", "/v1/admin/settings", map[string]any{"guest_first": true, "guest_first_channel": "#IRCForever"}, bearer(adminAT))
	e.expect(r, 200, "")
	if r.body["guest_first"] != true || r.str("guest_first_channel") != "#IRCForever" {
		t.Fatalf("patch: %s", r.raw)
	}
	tok := header("X-Internal-Token", e.cfg.InternalConfig.APIToken)
	if in := e.do(e.internal, "GET", "/internal/v1/settings", nil, tok); in.body["guest_first"] != true {
		t.Fatalf("internal: %s", in.raw)
	}
	if c := e.api("GET", "/v1/config", nil); c.body["guest_first"] != true || c.str("guest_first_channel") != "#IRCForever" {
		t.Fatalf("/v1/config: %s", c.raw)
	}

	// guest_first needs guest_access.
	r = e.api("PATCH", "/v1/admin/settings", map[string]any{"guest_access": false}, bearer(adminAT))
	e.expect(r, 400, "invalid_request")
	for bad, msg := range map[string]string{
		`{"guest_first": "yes"}`:           "guest_first must be a boolean",
		`{"guest_first_channel": "lobby"}`: `guest_first_channel: channel "lobby" must start with # and have a name`,
	} {
		r := e.api("PATCH", "/v1/admin/settings", json.RawMessage(bad), bearer(adminAT))
		e.expect(r, 400, "invalid_request")
		if r.str("message") != msg {
			t.Errorf("%s: message %q, want %q", bad, r.str("message"), msg)
		}
	}
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"guest_access": false, "guest_first": false}, bearer(adminAT)), 200, "")
	if c := e.api("GET", "/v1/config", nil); c.body["guest_first"] != false || c.body["guest_access"] != false {
		t.Fatalf("/v1/config after off: %s", c.raw)
	}
}

func TestGuestFirstConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boson.yaml")
	writeConfig(t, path, "version: 1\nauth:\n  guest_access: true\n  guest_first: true\n"+
		"irc:\n  channels:\n    - {name: \"#staff\", autojoin: true, roles: [Admin]}\n    - {name: \"#IRCForever\", autojoin: true}\n")
	e := newEnv(t, func(c *config.Config) {
		c.AppConfig.ConfigFile = path
		c.AppConfig.ConfigPoll = 200 * time.Millisecond
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.app.StackConfig.Run(ctx)

	// No guest_first_channel: the first auto-join channel guests may join.
	if c := e.api("GET", "/v1/config", nil); c.body["guest_first"] != true || c.str("guest_first_channel") != "#IRCForever" {
		t.Fatalf("/v1/config: %s", c.raw)
	}
	writeConfig(t, path, "version: 1\nauth:\n  guest_first: true\n  guest_first_channel: \"#help\"\n")
	eventually(t, "guest_first_channel from the file", func() bool {
		return e.api("GET", "/v1/config", nil).str("guest_first_channel") == "#help"
	})
	// A restricted landing channel is refused; the last good config stays.
	writeConfig(t, path, "version: 1\nauth:\n  guest_first: true\n  guest_first_channel: \"#staff\"\n"+
		"irc:\n  channels:\n    - {name: \"#staff\", roles: [Admin]}\n")
	time.Sleep(600 * time.Millisecond)
	if c := e.api("GET", "/v1/config", nil); c.str("guest_first_channel") != "#help" {
		t.Fatalf("restricted channel must be refused: %s", c.raw)
	}
	// Removing the keys turns it off.
	writeConfig(t, path, "version: 1\nauth:\n  guest_access: true\n")
	eventually(t, "guest_first back to default", func() bool {
		c := e.api("GET", "/v1/config", nil)
		return c.body["guest_first"] == false && c.body["guest_first_channel"] == nil
	})
}
