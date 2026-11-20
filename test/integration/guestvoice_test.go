package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/golang-jwt/jwt/v5"
)

const guestID = "Gx7_k2-Qm9vT4pLw"

func guestReq(nick string, rooms ...string) map[string]any {
	b := map[string]any{"nick": nick, "guest_id": guestID}
	if rooms != nil {
		b["rooms"] = rooms
	}
	return b
}

// newGuestVoiceEnv trusts the loopback proxy so each case can send its own
// X-Forwarded-For and get a fresh per-IP rate limit bucket.
func newGuestVoiceEnv(t *testing.T, guestAccess, guestVoice bool) *env {
	return newEnv(t, func(c *config.Config) {
		c.AccountConfig.GuestAccess = guestAccess
		c.AccountConfig.GuestVoice = guestVoice
		c.AccountConfig.SettingsCacheTTL = 0
		c.HTTPConfig.TrustedProxies = "127.0.0.1/32,::1/128"
	})
}

func xff(ip string) opt { return header("X-Forwarded-For", ip) }

func TestGuestVoiceTokenDisabled(t *testing.T) {
	for _, c := range []struct{ access, voice bool }{{true, false}, {false, true}, {false, false}} {
		e := newGuestVoiceEnv(t, c.access, c.voice)
		e.expect(e.api("POST", "/v1/voice/guest-token", guestReq("Wanderer"), xff("203.0.113.1")), 403, "guest_voice_disabled")
		if r := e.api("GET", "/v1/config", nil); r.body["guest_voice"] != false {
			t.Fatalf("access=%v voice=%v: /v1/config guest_voice must be false: %s", c.access, c.voice, r.raw)
		}
	}
}

func TestGuestVoiceToken(t *testing.T) {
	e := newGuestVoiceEnv(t, true, true)
	if r := e.api("GET", "/v1/config", nil); r.body["guest_voice"] != true {
		t.Fatalf("/v1/config guest_voice: %s", r.raw)
	}
	e.registerVerified("alice", "alice@example.com")

	// Success: a quicvoice token for the guest, verifiable with the JWKS.
	r := e.api("POST", "/v1/voice/guest-token", guestReq("Wanderer", "lobby"), xff("203.0.113.10"))
	e.expect(r, 200, "")
	if r.str("audience") != "quicvoice" || r.body["expires_in"].(float64) < 240 || r.body["expires_in"].(float64) > 300 {
		t.Fatalf("response: %s", r.raw)
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(r.str("token"), claims, e.jwksKeyfunc(), jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(issuer), jwt.WithAudience("quicvoice"), jwt.WithExpirationRequired()); err != nil {
		t.Fatalf("guest token does not verify against JWKS: %v", err)
	}
	if claims["sub"] != "guest:"+guestID || claims["name"] != "Wanderer" || claims["guest"] != true || claims["role"] != "speaker" {
		t.Fatalf("claims %v", claims)
	}
	if roles, ok := claims["roles"].([]any); !ok || len(roles) != 0 {
		t.Fatalf("roles %#v", claims["roles"])
	}
	if perms, ok := claims["perms"].([]any); !ok || len(perms) != 0 {
		t.Fatalf("perms %#v", claims["perms"])
	}
	if rooms, _ := claims["rooms"].([]any); len(rooms) != 1 || rooms[0] != "lobby" {
		t.Fatalf("rooms %v", claims["rooms"])
	}
	// No body rooms: any room.
	r = e.api("POST", "/v1/voice/guest-token", map[string]any{"nick": "w[a]nderer2", "guest_id": guestID}, xff("203.0.113.10"))
	e.expect(r, 200, "")
	// A guest token is not an access token.
	e.expect(e.api("GET", "/v1/me", nil, bearer(r.str("token"))), 401, "unauthenticated")

	// 400s.
	long := make([]byte, 65)
	for i := range long {
		long[i] = 'a'
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = fmt.Sprint("r", i)
	}
	for name, body := range map[string]any{
		"empty nick":       map[string]any{"nick": "", "guest_id": guestID},
		"nick digit first": guestReq("1abc"),
		"nick space":       guestReq("a b"),
		"nick too long":    guestReq("abcdefghijabcdefghijabcdefghijX"),
		"nick unicode":     guestReq("wänderer"),
		"no guest_id":      map[string]any{"nick": "Wanderer"},
		"short guest_id":   map[string]any{"nick": "Wanderer", "guest_id": "abc"},
		"long guest_id":    map[string]any{"nick": "Wanderer", "guest_id": string(long)},
		"bad guest_id":     map[string]any{"nick": "Wanderer", "guest_id": "Gx7_k2-Qm9vT4pL!"},
		"empty room":       guestReq("Wanderer", ""),
		"too many rooms":   guestReq("Wanderer", many...),
	} {
		r := e.api("POST", "/v1/voice/guest-token", body, xff("203.0.113.20"))
		if r.status != 400 || r.str("error") != "invalid_request" {
			t.Errorf("%s: %d %s", name, r.status, r.raw)
		}
	}

	// 409: registered (any case / RFC 1459 fold) or reserved nicks.
	for _, n := range []string{"alice", "ALICE", "NickServ", "chanserv"} {
		r := e.api("POST", "/v1/voice/guest-token", guestReq(n), xff("203.0.113.30"))
		if r.status != 409 || r.str("error") != "nick_registered" {
			t.Errorf("%s: %d %s", n, r.status, r.raw)
		}
	}
	// A disabled account still holds its name.
	adminAT := e.adminToken("netadmin")
	bob := e.registerVerified("b[o]b", "bob@example.com")
	e.expect(e.api("POST", "/v1/admin/users/"+bob+"/disable", nil, bearer(adminAT)), 200, "")
	e.expect(e.api("POST", "/v1/voice/guest-token", guestReq("B{O}B"), xff("203.0.113.30")), 409, "nick_registered")

	// Turning guest_voice off takes effect at once; guest_access off too.
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"guest_access": false}, bearer(adminAT)), 200, "")
	e.expect(e.api("POST", "/v1/voice/guest-token", guestReq("Wanderer"), xff("203.0.113.40")), 403, "guest_voice_disabled")
	if r := e.api("GET", "/v1/config", nil); r.body["guest_voice"] != false || r.body["guest_access"] != false {
		t.Fatalf("/v1/config: %s", r.raw)
	}
}

func TestGuestVoiceTokenRateLimit(t *testing.T) {
	e := newGuestVoiceEnv(t, true, true)
	ok := 0
	var last resp
	for range 25 {
		last = e.api("POST", "/v1/voice/guest-token", guestReq("Wanderer"), xff("198.51.100.7"))
		if last.status == 200 {
			ok++
		}
	}
	if ok != 20 || last.status != 429 || last.str("error") != "rate_limited" || last.header.Get("Retry-After") == "" {
		t.Fatalf("allowed %d, last %d %s", ok, last.status, last.raw)
	}
	// Per client IP (X-Forwarded-For from a trusted proxy).
	e.expect(e.api("POST", "/v1/voice/guest-token", guestReq("Wanderer"), xff("198.51.100.8")), 200, "")
	// Invalid requests count too.
	for range 20 {
		e.api("POST", "/v1/voice/guest-token", guestReq("1bad"), xff("198.51.100.9"))
	}
	e.expect(e.api("POST", "/v1/voice/guest-token", guestReq("Wanderer"), xff("198.51.100.9")), 429, "rate_limited")
}

func TestGuestVoiceSetting(t *testing.T) {
	e := newGuestVoiceEnv(t, true, false)
	adminAT := e.adminToken("netadmin")
	tok := header("X-Internal-Token", e.cfg.InternalConfig.APIToken)
	check := func(stored, public bool) {
		t.Helper()
		for name, r := range map[string]resp{
			"admin":    e.api("GET", "/v1/admin/settings", nil, bearer(adminAT)),
			"internal": e.do(e.internal, "GET", "/internal/v1/settings", nil, tok),
		} {
			e.expect(r, 200, "")
			if r.body["guest_voice"] != stored {
				t.Fatalf("%s: guest_voice want %v: %s", name, stored, r.raw)
			}
		}
		if r := e.api("GET", "/v1/config", nil); r.body["guest_voice"] != public {
			t.Fatalf("/v1/config guest_voice want %v: %s", public, r.raw)
		}
	}
	check(false, false)

	for bad, msg := range map[string]string{
		`{"guest_voice": "yes"}`: "guest_voice must be a boolean",
		`{"guest_voice": null}`:  "nothing to update",
	} {
		r := e.api("PATCH", "/v1/admin/settings", json.RawMessage(bad), bearer(adminAT))
		e.expect(r, 400, "invalid_request")
		if r.str("message") != msg {
			t.Errorf("%s: message %q, want %q", bad, r.str("message"), msg)
		}
	}

	r := e.api("PATCH", "/v1/admin/settings", map[string]any{"guest_voice": true}, bearer(adminAT))
	e.expect(r, 200, "")
	if r.body["guest_voice"] != true || r.body["guest_access"] != true {
		t.Fatalf("patch: %s", r.raw)
	}
	check(true, true)
	a := e.api("GET", "/v1/admin/audit?event=settings_updated&limit=1", nil, bearer(adminAT))
	if entries := a.list("entries"); len(entries) != 1 ||
		fmt.Sprint(entries[0]["meta"].(map[string]any)["new"]) != "map[guest_voice:true]" {
		t.Fatalf("audit: %s", a.raw)
	}
	// Stored but not effective without guest access.
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"guest_access": false}, bearer(adminAT)), 200, "")
	check(true, false)
}

func TestGuestVoiceConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boson.yaml")
	writeConfig(t, path, "version: 1\nauth:\n  guest_access: true\n  guest_voice: true\n")
	e := newEnv(t, func(c *config.Config) {
		c.AppConfig.ConfigFile = path
		c.AppConfig.ConfigPoll = 200 * time.Millisecond
		c.HTTPConfig.TrustedProxies = "127.0.0.1/32,::1/128"
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.app.StackConfig.Run(ctx)
	adminAT := e.adminToken("netadmin")

	r := e.api("GET", "/v1/admin/settings", nil, bearer(adminAT))
	if r.str("source") != "file" || r.body["guest_voice"] != true {
		t.Fatalf("admin settings: %s", r.raw)
	}
	if c := e.api("GET", "/v1/config", nil); c.body["guest_voice"] != true {
		t.Fatalf("/v1/config: %s", c.raw)
	}
	e.expect(e.api("POST", "/v1/voice/guest-token", guestReq("Wanderer"), xff("192.0.2.1")), 200, "")
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"guest_voice": false}, bearer(adminAT)), 409, "managed_by_config_file")

	// Removing the key falls back to the default (off).
	writeConfig(t, path, "version: 1\nauth:\n  guest_access: true\n")
	eventually(t, "guest_voice back to default", func() bool {
		return e.api("GET", "/v1/config", nil).body["guest_voice"] == false
	})
	e.expect(e.api("POST", "/v1/voice/guest-token", guestReq("Wanderer"), xff("192.0.2.1")), 403, "guest_voice_disabled")
}
