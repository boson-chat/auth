package integration

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
)

func channelNames(r resp) string {
	var out []string
	for _, c := range r.list("channels") {
		out = append(out, fmt.Sprintf("%v:%v", c["channel"], c["private"]))
	}
	return fmt.Sprint(out)
}

func TestRoleChannelsAdminAPI(t *testing.T) {
	e := newEnv(t)
	ownerAT := e.ownerToken("boss")
	modAT := e.roleToken("moddy", "user")
	plainAT := e.roleToken("plain", "user")
	modID := e.userID(modAT)

	mods := e.api("POST", "/v1/admin/roles", map[string]any{"name": "Mods", "position": 500, "permissions": []string{"admin.panel", "roles.manage"}}, bearer(ownerAT))
	e.expect(mods, 201, "")
	modsRole := mods.str("role", "id")
	dj := e.api("POST", "/v1/admin/roles", map[string]any{"name": "DJ", "position": 100}, bearer(ownerAT))
	e.expect(dj, 201, "")
	djRole := dj.str("role", "id")
	e.expect(e.api("PUT", "/v1/admin/users/"+modID+"/roles", map[string]any{"role_ids": []string{modsRole}}, bearer(ownerAT)), 200, "")

	// Auth: Bearer with admin.panel/roles.manage only.
	e.expect(e.api("GET", "/v1/admin/channel-access", nil), 401, "unauthenticated")
	e.expect(e.api("GET", "/v1/admin/channel-access", nil, bearer(plainAT)), 403, "forbidden")
	e.expect(e.api("PUT", "/v1/admin/roles/everyone/channels", []any{}, bearer(plainAT)), 403, "forbidden")

	// A bare list, or {"channels": [...]}; autojoin defaults to true.
	r := e.api("PUT", "/v1/admin/roles/"+modsRole+"/channels", []map[string]any{{"channel": "#Staff"}, {"channel": "#ops", "autojoin": false}}, bearer(ownerAT))
	e.expect(r, 200, "")
	if r.str("role_id") != modsRole || fmt.Sprint(r.body["channels"]) != "[map[autojoin:false channel:#ops private:false] map[autojoin:true channel:#staff private:false]]" {
		t.Fatalf("mods channels: %s", r.raw)
	}
	r = e.api("PUT", "/v1/admin/roles/everyone/channels", map[string]any{"channels": []map[string]any{{"channel": "#lobby"}}}, bearer(ownerAT))
	e.expect(r, 200, "")
	if r.str("role_id") != "everyone" {
		t.Fatalf("everyone: %s", r.raw)
	}
	e.expect(e.api("PUT", "/v1/admin/roles/"+djRole+"/channels", []map[string]any{{"channel": "#staff"}, {"channel": "#music"}}, bearer(ownerAT)), 200, "")
	e.expect(e.api("PUT", "/v1/admin/roles/"+djRole+"/channels", []map[string]any{{"channel": "no-hash"}}, bearer(ownerAT)), 400, "invalid_request")
	e.expect(e.api("PUT", "/v1/admin/roles/rol_00000000000000000000000099/channels", []any{}, bearer(ownerAT)), 404, "not_found")
	// Hierarchy: Mods can't edit their own role's channels, but can DJ's.
	e.expect(e.api("PUT", "/v1/admin/roles/"+modsRole+"/channels", []any{}, bearer(modAT)), 403, "role_hierarchy")
	e.expect(e.api("GET", "/v1/admin/roles/"+djRole+"/channels", nil, bearer(modAT)), 200, "")

	// Mark private.
	r = e.api("PUT", "/v1/admin/channel-access", []map[string]any{{"channel": "#staff", "private": true}, {"channel": "#Secret", "private": true}, {"channel": "#lobby", "private": false}}, bearer(modAT))
	e.expect(r, 200, "")
	if got := channelNames(r); got != "[#lobby:false #music:false #ops:false #secret:true #staff:true]" {
		t.Fatalf("access: %s", got)
	}
	g := e.api("GET", "/v1/admin/channel-access", nil, bearer(ownerAT))
	for _, c := range g.list("channels") {
		if c["channel"] == "#staff" && fmt.Sprint(c["roles"]) != fmt.Sprintf("[map[autojoin:true id:%s name:Mods] map[autojoin:true id:%s name:DJ]]", modsRole, djRole) {
			t.Fatalf("#staff roles: %v", c["roles"])
		}
	}
	if r := e.api("GET", "/v1/admin/roles/"+modsRole+"/channels", nil, bearer(ownerAT)); fmt.Sprint(r.body["channels"]) != "[map[autojoin:false channel:#ops private:false] map[autojoin:true channel:#staff private:true]]" {
		t.Fatalf("role channels private flag: %s", r.raw)
	}

	// Audited.
	a := e.api("GET", "/v1/admin/audit?event=channel_access_updated", nil, bearer(ownerAT))
	e.expect(a, 200, "")
	if len(a.list("entries")) != 1 {
		t.Fatalf("audit: %s", a.raw)
	}
	a = e.api("GET", "/v1/admin/audit?event=role_channels_updated", nil, bearer(ownerAT))
	if len(a.list("entries")) != 3 {
		t.Fatalf("audit role channels: %s", a.raw)
	}

	// Deleting a role drops its channels.
	e.expect(e.api("DELETE", "/v1/admin/roles/"+djRole, nil, bearer(ownerAT)), 204, "")
	if got := channelNames(e.api("GET", "/v1/admin/channel-access", nil, bearer(ownerAT))); got != "[#lobby:false #ops:false #secret:true #staff:true]" {
		t.Fatalf("after delete: %s", got)
	}

	// GET /v1/me/channels: with the roles that give them.
	me := e.api("GET", "/v1/me/channels", nil, bearer(modAT))
	e.expect(me, 200, "")
	if fmt.Sprint(me.body["channels"]) != "[map[autojoin:true channel:#lobby private:false via:[Everyone]] map[autojoin:false channel:#ops private:false via:[Mods]] map[autojoin:true channel:#staff private:true via:[Mods]]]" {
		t.Fatalf("me/channels: %s", me.raw)
	}
	e.expect(e.api("GET", "/v1/me/channels", nil), 401, "unauthenticated")
}

func TestRoleChannelsInternalFeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boson.yaml")
	writeConfig(t, path, "version: 1\n")
	e := newEnv(t, func(c *config.Config) {
		c.AppConfig.ConfigFile = path
		c.AppConfig.ConfigPoll = 200 * time.Millisecond
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.app.StackConfig.Run(ctx)
	ownerAT := e.ownerToken("boss")
	aliceAT := e.roleToken("Alice", "user")
	bobAT := e.roleToken("bob", "user")
	aliceID, bobID := e.userID(aliceAT), e.userID(bobAT)
	staff := e.api("POST", "/v1/admin/roles", map[string]any{"name": "Staff", "position": 200}, bearer(ownerAT))
	e.expect(staff, 201, "")
	staffRole := staff.str("role", "id")
	e.expect(e.api("PUT", "/v1/admin/roles/"+staffRole+"/channels", []map[string]any{{"channel": "#staff"}}, bearer(ownerAT)), 200, "")
	e.expect(e.api("PUT", "/v1/admin/roles/everyone/channels", []map[string]any{{"channel": "#lobby"}}, bearer(ownerAT)), 200, "")
	e.expect(e.api("PUT", "/v1/admin/channel-access", []map[string]any{{"channel": "#staff", "private": true}}, bearer(ownerAT)), 200, "")

	// Internal token only.
	e.expect(e.do(e.internal, "GET", "/internal/v1/irc/channel-access", nil), 401, "")
	e.expect(e.api("GET", "/internal/v1/irc/channel-access", nil, header("X-Internal-Token", e.cfg.InternalConfig.APIToken)), 404, "")

	version := ""
	feed := func(wantStatus int) resp {
		t.Helper()
		var opts []opt
		if version != "" {
			opts = append(opts, header("If-None-Match", `"`+version+`"`))
		}
		r := e.internalAPI("GET", "/internal/v1/irc/channel-access", nil, opts...)
		if r.status != wantStatus {
			t.Fatalf("feed: want %d, got %d %s", wantStatus, r.status, r.raw)
		}
		if r.status == 200 {
			if v := r.str("version"); v == "" || v == version || r.header.Get("ETag") != `"`+v+`"` {
				t.Fatalf("version/ETag: %s %v (was %s)", r.raw, r.header, version)
			}
			version = r.str("version")
		}
		return r
	}
	staffAccounts := func(r resp) string {
		for _, c := range r.list("channels") {
			if c["channel"] == "#staff" {
				return fmt.Sprint(c["accounts"])
			}
		}
		return "missing"
	}
	r := feed(200)
	if r.body["autojoin"] != false || r.str("rejoin") != "login" || staffAccounts(r) != "[]" {
		t.Fatalf("initial feed: %s", r.raw)
	}
	feed(304)

	// Gaining the role bumps the version and lists the (lower-cased) account.
	e.expect(e.api("PUT", "/v1/admin/users/"+aliceID+"/roles", map[string]any{"role_ids": []string{staffRole}}, bearer(ownerAT)), 200, "")
	if r := feed(200); staffAccounts(r) != "[alice]" {
		t.Fatalf("after grant: %s", r.raw)
	}
	// Settings from the config file (hot reload) bump it too.
	writeConfig(t, path, "version: 1\nroles:\n  channels:\n    autojoin: true\n    rejoin: once\n")
	eventually(t, "settings in the feed", func() bool {
		r := e.internalAPI("GET", "/internal/v1/irc/channel-access", nil)
		return r.body["autojoin"] == true && r.str("rejoin") == "once"
	})
	feed(200)

	// Per-account auto-join.
	aj := e.internalAPI("GET", "/internal/v1/irc/autojoin?account=ALICE", nil)
	e.expect(aj, 200, "")
	if aj.str("account") != "Alice" || aj.body["enabled"] != true || aj.str("rejoin") != "once" ||
		fmt.Sprint(aj.body["channels"]) != "[#lobby #staff]" || fmt.Sprint(aj.body["pending"]) != "[#lobby #staff]" {
		t.Fatalf("autojoin: %s", aj.raw)
	}
	if b := e.internalAPI("GET", "/internal/v1/irc/autojoin?account=bob", nil); fmt.Sprint(b.body["channels"]) != "[#lobby]" {
		t.Fatalf("bob: %s", b.raw)
	}
	e.expect(e.internalAPI("GET", "/internal/v1/irc/autojoin?account=ghost", nil), 404, "not_found")
	e.expect(e.internalAPI("GET", "/internal/v1/irc/autojoin", nil), 400, "invalid_request")

	// rejoin: once records.
	rec := e.internalAPI("POST", "/internal/v1/irc/autojoin", map[string]any{"account": "alice", "channels": []string{"#Staff", "#nope"}})
	e.expect(rec, 200, "")
	if fmt.Sprint(rec.body["pending"]) != "[#lobby]" {
		t.Fatalf("record: %s", rec.raw)
	}
	// Losing the role prunes #staff (on the next record), so regaining it auto-joins again.
	e.expect(e.api("PUT", "/v1/admin/users/"+aliceID+"/roles", map[string]any{"role_ids": []string{}}, bearer(ownerAT)), 200, "")
	if r := feed(200); staffAccounts(r) != "[]" {
		t.Fatalf("after revoke: %s", r.raw)
	}
	e.expect(e.internalAPI("POST", "/internal/v1/irc/autojoin", map[string]any{"account": "alice", "channels": []string{"#lobby"}}), 200, "")
	e.expect(e.api("PUT", "/v1/admin/users/"+aliceID+"/roles", map[string]any{"role_ids": []string{staffRole}}, bearer(ownerAT)), 200, "")
	if aj := e.internalAPI("GET", "/internal/v1/irc/autojoin?account=alice", nil); fmt.Sprint(aj.body["pending"]) != "[#staff]" {
		t.Fatalf("after regain: %s", aj.raw)
	}

	// Disabling bob, then deleting him, keeps the feed consistent.
	e.expect(e.api("PUT", "/v1/admin/users/"+bobID+"/roles", map[string]any{"role_ids": []string{staffRole}}, bearer(ownerAT)), 200, "")
	if r := feed(200); staffAccounts(r) != "[alice bob]" {
		t.Fatalf("bob added: %s", r.raw)
	}
	e.expect(e.api("POST", "/v1/admin/users/"+bobID+"/disable", nil, bearer(ownerAT)), 200, "")
	if r := feed(200); staffAccounts(r) != "[alice]" {
		t.Fatalf("bob disabled: %s", r.raw)
	}

	// Everyone on a private channel: every account may join.
	e.expect(e.api("PUT", "/v1/admin/channel-access", []map[string]any{{"channel": "#staff", "private": true}, {"channel": "#lobby", "private": true}}, bearer(ownerAT)), 200, "")
	for _, c := range feed(200).list("channels") {
		if c["channel"] == "#lobby" && (c["everyone"] != true || fmt.Sprint(c["accounts"]) != "[]") {
			t.Fatalf("#lobby: %v", c)
		}
	}
}

func TestRoleChannelsMigrationConstraints(t *testing.T) {
	e := newEnv(t)
	sqldb, err := sql.Open("pgx", e.cfg.DBConfig.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer sqldb.Close()
	for _, bad := range []string{"#Upper", "nohash", "#a b", "#a,b", "#"} {
		if _, err := sqldb.Exec(`INSERT INTO channel_access (channel) VALUES ($1)`, bad); err == nil {
			t.Errorf("channel_access accepted %q", bad)
		}
	}
	if _, err := sqldb.Exec(`INSERT INTO role_channels (role_id, channel) VALUES ('rol_00000000000000000000000004', '#ok')`); err != nil {
		t.Fatal(err)
	}
	if _, err := sqldb.Exec(`INSERT INTO role_channels (role_id, channel) VALUES ('rol_missing', '#ok')`); err == nil {
		t.Fatal("role_channels accepted an unknown role")
	}
}

// Network channels (config irc:): the feed's network part, the founder
// fallback to the earliest Owner, once-only auto-join and GET /v1/config.
func TestNetworkChannels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boson.yaml")
	writeConfig(t, path, "version: 1\n")
	e := newEnv(t, func(c *config.Config) {
		c.AppConfig.ConfigFile = path
		c.AppConfig.ConfigPoll = 200 * time.Millisecond
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.app.StackConfig.Run(ctx)
	firstAT := e.ownerToken("FirstBoss")
	secondAT := e.ownerToken("secondboss")
	e.roleToken("carol", "user")

	r := e.internalAPI("GET", "/internal/v1/irc/channel-access", nil)
	e.expect(r, 200, "")
	if fmt.Sprint(r.body["network"]) != "map[autojoin_guests:true channels:[] founder:FirstBoss]" {
		t.Fatalf("no network channels: %s", r.raw)
	}
	if c := e.api("GET", "/v1/config", nil); fmt.Sprint(c.body["channels"]) != "[]" {
		t.Fatalf("config channels: %s", c.raw)
	}
	v0 := r.str("version")

	writeConfig(t, path, "version: 1\nirc:\n  plaintext: true\n  channels:\n    - { name: \"#Lobby\", topic: Welcome, autojoin: true }\n    - { name: \"#help\" }\n")
	eventually(t, "network channels in the feed", func() bool {
		r = e.internalAPI("GET", "/internal/v1/irc/channel-access", nil)
		return r.str("version") != v0
	})
	if fmt.Sprint(r.body["network"]) != "map[autojoin_guests:true channels:[map[autojoin:true channel:#lobby name:#Lobby topic:Welcome] map[autojoin:false channel:#help name:#help topic:]] founder:FirstBoss]" {
		t.Fatalf("network: %s", r.raw)
	}
	if c := e.api("GET", "/v1/config", nil); fmt.Sprint(c.body["channels"]) != "[map[autojoin:true name:#Lobby topic:Welcome] map[autojoin:false name:#help topic:]]" {
		t.Fatalf("config channels: %s", c.raw)
	}
	// The first owner losing Owner: the next one founds.
	e.expect(e.api("PUT", "/v1/admin/users/"+e.userID(firstAT)+"/roles", map[string]any{"role_ids": []string{}}, bearer(secondAT)), 200, "")
	if r := e.internalAPI("GET", "/internal/v1/irc/channel-access", nil); r.str("network", "founder") != "secondboss" {
		t.Fatalf("next owner: %s", r.raw)
	}

	// Once-only, with roles.channels.autojoin off.
	aj := e.internalAPI("GET", "/internal/v1/irc/autojoin?account=carol", nil)
	if aj.body["enabled"] != false || fmt.Sprint(aj.body["network"]) != "[#lobby]" || fmt.Sprint(aj.body["network_pending"]) != "[#lobby]" {
		t.Fatalf("autojoin: %s", aj.raw)
	}
	rec := e.internalAPI("POST", "/internal/v1/irc/autojoin", map[string]any{"account": "carol", "channels": []string{"#LOBBY"}})
	e.expect(rec, 200, "")
	if fmt.Sprint(rec.body["network_pending"]) != "[]" {
		t.Fatalf("record: %s", rec.raw)
	}
	// Recording role channels later keeps the network row.
	e.expect(e.internalAPI("POST", "/internal/v1/irc/autojoin", map[string]any{"account": "carol", "channels": []string{}}), 200, "")
	if aj := e.internalAPI("GET", "/internal/v1/irc/autojoin?account=carol", nil); fmt.Sprint(aj.body["network_pending"]) != "[]" {
		t.Fatalf("kept: %s", aj.raw)
	}

	// The founder from the file wins; guests can be turned off.
	writeConfig(t, path, "version: 1\nirc:\n  channels: [{ name: \"#lobby\", autojoin: true }]\n  channel_founder: thelion\n  autojoin_guests: false\n")
	eventually(t, "founder from the file", func() bool {
		r := e.internalAPI("GET", "/internal/v1/irc/channel-access", nil)
		return r.str("network", "founder") == "thelion" && r.body["network"].(map[string]any)["autojoin_guests"] == false
	})
}
