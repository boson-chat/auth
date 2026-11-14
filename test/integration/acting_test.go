package integration

import (
	"database/sql"
	"fmt"
	"slices"
	"testing"

	"github.com/boson-chat/auth/config"
)

func withActingToken(c *config.Config) { c.InternalConfig.ActingToken = randHex(32) }

// acting calls /internal/v1/acting as account (RoleServ).
func (e *env) acting(account, method, path string, body any, opts ...opt) resp {
	e.t.Helper()
	return e.do(e.internal, method, "/internal/v1/acting"+path, body, append([]opt{
		header("X-Internal-Token", e.cfg.InternalConfig.ActingToken),
		header("X-Acting-Account", account), header("X-Acting-Via", "roleserv"),
	}, opts...)...)
}

func TestActingAPIAuth(t *testing.T) {
	e := newEnv(t, withActingToken)
	e.ownerToken("boss")
	aliceAT := e.adminToken("alice")
	bobID := e.registerVerified("bob", "bob@example.com")

	// Only INTERNAL_ACTING_TOKEN, never INTERNAL_API_TOKEN.
	e.expect(e.do(e.internal, "GET", "/internal/v1/acting/me", nil, header("X-Acting-Account", "alice")), 401, "unauthenticated")
	e.expect(e.do(e.internal, "GET", "/internal/v1/acting/me", nil, header("X-Acting-Account", "alice"),
		header("X-Internal-Token", e.cfg.InternalConfig.APIToken)), 401, "unauthenticated")
	// And the acting token doesn't open the rest of the internal API.
	e.expect(e.do(e.internal, "GET", "/internal/v1/roles", nil, header("X-Internal-Token", e.cfg.InternalConfig.ActingToken)), 401, "")
	// Not on the public listener.
	e.expect(e.api("GET", "/internal/v1/acting/me", nil, header("X-Internal-Token", e.cfg.InternalConfig.ActingToken), header("X-Acting-Account", "alice")), 404, "")

	// The acting account is matched with RFC 1459 folding.
	me := e.acting("ALICE", "GET", "/me", nil)
	e.expect(me, 200, "")
	if me.str("username") != "alice" || !slices.Contains(strs(me.body["permissions"]), "roles.manage") ||
		slices.Contains(strs(me.body["permissions"]), "roles.owner") {
		t.Fatalf("me: %s", me.raw)
	}
	b := e.acting("bob", "GET", "/me", nil)
	e.expect(b, 200, "")
	if fmt.Sprint(b.body["permissions"]) != "[channel.create voice.create]" {
		t.Fatalf("bob me: %s", b.raw)
	}

	// Unknown, missing or disabled acting accounts are forbidden.
	e.expect(e.acting("ghost", "GET", "/me", nil), 403, "forbidden")
	e.expect(e.acting("", "GET", "/me", nil), 403, "forbidden")
	e.expect(e.api("POST", "/v1/admin/users/"+bobID+"/disable", nil, bearer(aliceAT)), 200, "")
	e.expect(e.acting("bob", "GET", "/me", nil), 403, "forbidden")
	// Errors carry the code twice ("error" and "code").
	if r := e.acting("ghost", "GET", "/me", nil); r.str("code") != "forbidden" {
		t.Fatalf("code: %s", r.raw)
	}
}

func TestActingAPIDisabledWithoutToken(t *testing.T) {
	e := newEnv(t)
	e.ownerToken("boss")
	for _, tok := range []string{"", e.cfg.InternalConfig.APIToken} {
		r := e.do(e.internal, "GET", "/internal/v1/acting/me", nil, header("X-Internal-Token", tok), header("X-Acting-Account", "boss"))
		if r.status != 404 || r.str("code") != "" {
			t.Fatalf("acting API without INTERNAL_ACTING_TOKEN: %d %s", r.status, r.raw)
		}
	}
	e.expect(e.do(e.internal, "PUT", "/internal/v1/acting/users/x/roles", map[string]any{"role_ids": []string{}},
		header("X-Internal-Token", e.cfg.InternalConfig.APIToken), header("X-Acting-Account", "boss")), 404, "")
}

func TestActingAPIRoles(t *testing.T) {
	e := newEnv(t, withActingToken)
	ownerAT := e.ownerToken("boss")
	aliceAT := e.adminToken("alice")
	aliceID := e.userID(aliceAT)
	bobID := e.registerVerified("bob", "bob@example.com")
	carolID := e.userID(e.adminToken("carol"))

	// Without roles.manage: 403 forbidden on every write.
	e.expect(e.acting("bob", "POST", "/roles", map[string]any{"name": "DJ"}), 403, "forbidden")
	e.expect(e.acting("bob", "PUT", "/users/"+bobID+"/roles", map[string]any{"role_ids": []string{modRoleID}}), 403, "forbidden")

	// Create, as the admin API.
	c := e.acting("alice", "POST", "/roles", map[string]any{"name": "DJ", "permissions": []string{"voice.create"},
		"irc": map[string]any{"vhost": "dj/{username}"}})
	e.expect(c, 201, "")
	dj := c.body["role"].(map[string]any)
	djID := dj["id"].(string)
	if dj["slug"] != "dj" || dj["position"] != float64(1) || dj["irc"].(map[string]any)["vhost"] != "dj/{username}" {
		t.Fatalf("created: %s", c.raw)
	}
	e.expect(e.acting("alice", "POST", "/roles", map[string]any{"name": "dj"}), 409, "role_name_taken")
	e.expect(e.acting("alice", "POST", "/roles", map[string]any{"name": "bad.name"}), 400, "invalid_request")
	e.expect(e.acting("alice", "POST", "/roles", map[string]any{"name": "Big", "position": 950}), 403, "role_hierarchy")
	e.expect(e.acting("alice", "POST", "/roles", map[string]any{"name": "Heir", "permissions": []string{"roles.owner"}}), 403, "permission_not_held")

	// Patch: null clears; If-Match guards against lost updates.
	p := e.acting("alice", "PATCH", "/roles/"+djID, map[string]any{"color": "#00ff00", "irc": map[string]any{"whois_line": "is a DJ"}})
	e.expect(p, 200, "")
	updatedAt := p.str("role", "updated_at")
	p = e.acting("alice", "PATCH", "/roles/"+djID, map[string]any{"color": nil, "irc": map[string]any{"vhost": nil}},
		header("If-Match", `"`+updatedAt+`"`))
	e.expect(p, 200, "")
	if p.body["role"].(map[string]any)["color"] != nil || p.body["role"].(map[string]any)["irc"].(map[string]any)["vhost"] != nil {
		t.Fatalf("null must clear: %s", p.raw)
	}
	e.expect(e.acting("alice", "PATCH", "/roles/"+djID, map[string]any{"hoist": true}, header("If-Match", updatedAt)), 412, "precondition_failed")
	g := e.api("GET", "/v1/admin/roles/"+djID, nil, bearer(ownerAT))
	e.expect(e.acting("alice", "PATCH", "/roles/"+djID, map[string]any{"hoist": true}, header("If-Match", g.str("role", "updated_at"))), 200, "")
	e.expect(e.acting("alice", "PATCH", "/roles/"+djID, map[string]any{"hoist": true}, header("If-Match", "yesterday")), 400, "invalid_request")
	e.expect(e.acting("alice", "PATCH", "/roles/"+adminRoleID, map[string]any{"color": "#000000"}), 403, "role_hierarchy")
	e.expect(e.acting("alice", "PATCH", "/roles/"+djID, map[string]any{"permissions": []string{"roles.owner"}}), 403, "permission_not_held")
	e.expect(e.acting("alice", "PATCH", "/roles/"+djID, map[string]any{"position": 900}), 403, "role_hierarchy")
	e.expect(e.acting("alice", "PATCH", "/roles/rol_nope", map[string]any{"hoist": true}), 404, "not_found")
	// The owner may edit anything.
	e.expect(e.acting("boss", "PATCH", "/roles/"+adminRoleID, map[string]any{"irc": map[string]any{"vhost": "staff/{username}"}}), 200, "")

	// Assign: replaces; hierarchy on the target and the roles.
	s := e.acting("alice", "PUT", "/users/"+bobID+"/roles", map[string]any{"role_ids": []string{djID, modRoleID, memberRoleID}})
	e.expect(s, 200, "")
	if fmt.Sprint(ids(s.list("roles"))) != fmt.Sprint([]string{modRoleID, djID}) {
		t.Fatalf("set roles: %s", s.raw)
	}
	e.expect(e.acting("alice", "PUT", "/users/"+bobID+"/roles", map[string]any{"role_ids": []string{adminRoleID}}), 403, "role_hierarchy")
	e.expect(e.acting("alice", "PUT", "/users/"+carolID+"/roles", map[string]any{"role_ids": []string{}}), 403, "role_hierarchy")
	e.expect(e.acting("alice", "PUT", "/users/usr_nope/roles", map[string]any{"role_ids": []string{}}), 404, "not_found")
	e.expect(e.acting("alice", "PUT", "/users/"+bobID+"/roles", map[string]any{}), 400, "invalid_request")
	e.expect(e.acting("alice", "PUT", "/users/"+aliceID+"/roles", map[string]any{"role_ids": []string{adminRoleID, djID}}), 200, "")

	// Delete.
	e.expect(e.acting("alice", "DELETE", "/roles/"+memberRoleID, nil), 409, "builtin_role")
	e.expect(e.acting("alice", "DELETE", "/roles/"+djID, nil), 204, "")
	e.expect(e.acting("alice", "DELETE", "/roles/"+djID, nil), 404, "not_found")

	// Audited as the acting user, via roleserv.
	a := e.api("GET", "/v1/admin/audit?event=role_created,role_updated,role_deleted,user_roles_changed&limit=50", nil, bearer(ownerAT))
	e.expect(a, 200, "")
	seen := map[string]int{}
	for _, ev := range a.list("entries") {
		meta := ev["meta"].(map[string]any)
		if meta["via"] != "roleserv" {
			t.Fatalf("event without via: %v", ev)
		}
		actor := ev["actor_username"]
		if ev["event"] == "role_updated" && meta["role_id"] == adminRoleID {
			if actor != "boss" {
				t.Fatalf("owner's edit: %v", ev)
			}
		} else if actor != "alice" {
			t.Fatalf("actor: %v", ev)
		}
		seen[ev["event"].(string)]++
	}
	if seen["role_created"] != 1 || seen["role_updated"] != 4 || seen["role_deleted"] != 1 || seen["user_roles_changed"] != 2 {
		t.Fatalf("audit events: %v (%s)", seen, a.raw)
	}
	// Admin-panel changes have no via.
	e.expect(e.api("POST", "/v1/admin/roles", map[string]any{"name": "Panel"}, bearer(ownerAT)), 201, "")
	a = e.api("GET", "/v1/admin/audit?event=role_created&limit=1", nil, bearer(ownerAT))
	if m := a.list("entries")[0]["meta"].(map[string]any); m["via"] != nil {
		t.Fatalf("panel event has via: %v", m)
	}
}

func TestInternalRoleMembers(t *testing.T) {
	e := newEnv(t)
	ownerAT := e.ownerToken("boss")
	var want []string
	for i := range 3 {
		uid := e.registerVerified(fmt.Sprintf("mod%d", i), fmt.Sprintf("mod%d@example.com", i))
		e.expect(e.api("PUT", "/v1/admin/users/"+uid+"/roles", map[string]any{"role_ids": []string{modRoleID}}, bearer(ownerAT)), 200, "")
		want = append(want, uid)
	}
	slices.Sort(want)
	e.expect(e.do(e.internal, "GET", "/internal/v1/roles/"+modRoleID+"/members", nil), 401, "")
	var got []string
	cursor := ""
	for page := 0; ; page++ {
		r := e.internalAPI("GET", "/internal/v1/roles/"+modRoleID+"/members?limit=2&cursor="+cursor, nil)
		e.expect(r, 200, "")
		for _, u := range r.list("users") {
			if u["disabled"] != false || u["username"] == "" || u["assigned_at"] == nil {
				t.Fatalf("member: %v", u)
			}
			got = append(got, u["id"].(string))
		}
		next, _ := r.body["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("members %v, want %v", got, want)
	}
	if r := e.internalAPI("GET", "/internal/v1/roles/"+memberRoleID+"/members?limit=200", nil); len(r.list("users")) != 4 {
		t.Fatalf("Member members: %s", r.raw)
	}
	e.expect(e.internalAPI("GET", "/internal/v1/roles/rol_nope/members", nil), 404, "not_found")
	e.expect(e.internalAPI("GET", "/internal/v1/roles/"+modRoleID+"/members?limit=201", nil), 200, "")
	e.expect(e.internalAPI("GET", "/internal/v1/roles/"+modRoleID+"/members?cursor=!!", nil), 400, "invalid_request")
}

func TestIRCGrantsFeed(t *testing.T) {
	e := newEnv(t)
	ownerAT := e.ownerToken("boss")
	bobID := e.registerVerified("Bob[x]", "bob@example.com")
	carlID := e.registerVerified("carl", "carl@example.com")
	sqldb, err := sql.Open("pgx", e.cfg.DBConfig.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer sqldb.Close()

	e.expect(e.do(e.internal, "GET", "/internal/v1/irc/grants", nil), 401, "")
	get := func() resp {
		t.Helper()
		r := e.internalAPI("GET", "/internal/v1/irc/grants", nil)
		e.expect(r, 200, "")
		if v := r.str("version"); v == "" || r.header.Get("ETag") != `"`+v+`"` {
			t.Fatalf("version/ETag: %s %v", r.raw, r.header)
		}
		return r
	}
	users := func(r resp) string {
		var out []string
		for _, u := range r.list("users") {
			out = append(out, fmt.Sprintf("%v:%v:%v:%v", u["username"], u["oper_class"], u["whois_line"], u["vhost"]))
		}
		return fmt.Sprint(out)
	}
	r := get()
	if users(r) != "[boss:owner:is an Owner:<nil>]" {
		t.Fatalf("initial: %s", users(r))
	}
	version := r.str("version")
	if c := e.internalAPI("GET", "/internal/v1/irc/grants", nil, header("If-None-Match", `"`+version+`"`)); c.status != 304 ||
		c.header.Get("ETag") != `"`+version+`"` {
		t.Fatalf("If-None-Match: %d %v", c.status, c.header)
	}
	// changed asserts that what() bumps the version (and returns the new body).
	changed := func(name string, what func()) resp {
		t.Helper()
		what()
		r := e.internalAPI("GET", "/internal/v1/irc/grants", nil, header("If-None-Match", `"`+version+`"`))
		if r.status != 200 || r.str("version") == version {
			t.Fatalf("%s: version not bumped (%d %s)", name, r.status, r.raw)
		}
		version = r.str("version")
		return r
	}
	exec := func(q string, args ...any) func() {
		return func() {
			if _, err := sqldb.Exec(q, args...); err != nil {
				t.Fatal(err)
			}
		}
	}

	var djID string
	r = changed("role create", func() {
		c := e.api("POST", "/v1/admin/roles", map[string]any{"name": "DJ", "position": 10, "irc": map[string]any{"vhost": "dj/{username}"}}, bearer(ownerAT))
		e.expect(c, 201, "")
		djID = c.str("role", "id")
	})
	r = changed("assignment", func() {
		e.expect(e.api("PUT", "/v1/admin/users/"+bobID+"/roles", map[string]any{"role_ids": []string{djID}}, bearer(ownerAT)), 200, "")
	})
	if users(r) != "[Bob[x]:<nil>:<nil>:dj/bob-x- boss:owner:is an Owner:<nil>]" {
		t.Fatalf("after assignment: %s", users(r))
	}
	r = changed("role edit", func() {
		e.expect(e.api("PATCH", "/v1/admin/roles/"+djID, map[string]any{"permissions": []string{"irc.samode"}, "irc": map[string]any{"whois_line": "is a DJ"}}, bearer(ownerAT)), 200, "")
	})
	if users(r) != "[Bob[x]:dj:is a DJ:dj/bob-x- boss:owner:is an Owner:<nil>]" {
		t.Fatalf("after edit: %s", users(r))
	}
	// A vhost on Member puts every enabled account in the list.
	r = changed("member vhost", func() {
		e.expect(e.api("PATCH", "/v1/admin/roles/"+memberRoleID, map[string]any{"irc": map[string]any{"vhost": "users/{username}"}}, bearer(ownerAT)), 200, "")
	})
	if users(r) != "[Bob[x]:dj:is a DJ:dj/bob-x- boss:owner:is an Owner:users/boss carl:<nil>:<nil>:users/carl]" {
		t.Fatalf("member vhost: %s", users(r))
	}
	r = changed("disable", func() {
		e.expect(e.api("POST", "/v1/admin/users/"+carlID+"/disable", nil, bearer(ownerAT)), 200, "")
	})
	if users(r) != "[Bob[x]:dj:is a DJ:dj/bob-x- boss:owner:is an Owner:users/boss]" {
		t.Fatalf("disabled carl: %s", users(r))
	}
	changed("enable", func() {
		e.expect(e.api("POST", "/v1/admin/users/"+carlID+"/enable", nil, bearer(ownerAT)), 200, "")
	})
	r = changed("register", func() { e.registerVerified("dora", "dora@example.com") })
	if !slices.ContainsFunc(r.list("users"), func(u map[string]any) bool { return u["vhost"] == "users/dora" }) {
		t.Fatalf("new user: %s", users(r))
	}
	changed("reorder", func() {
		e.expect(e.api("POST", "/v1/admin/roles", map[string]any{"name": "Other", "position": 20}, bearer(ownerAT)), 201, "")
		r := e.api("GET", "/v1/admin/roles", nil, bearer(ownerAT))
		var custom []string
		for _, ro := range r.list("roles") {
			if ro["builtin"] == nil {
				custom = append(custom, ro["id"].(string))
			}
		}
		slices.Reverse(custom)
		e.expect(e.api("POST", "/v1/admin/roles/reorder", map[string]any{"order": custom}, bearer(ownerAT)), 200, "")
	})
	r = changed("rename", exec(`UPDATE users SET username = 'Carlos', username_folded = 'carlos' WHERE id = $1`, carlID))
	if !slices.ContainsFunc(r.list("users"), func(u map[string]any) bool { return u["vhost"] == "users/carlos" }) {
		t.Fatalf("rename: %s", users(r))
	}
	r = changed("user deletion", exec(`DELETE FROM users WHERE id = $1`, bobID))
	if slices.ContainsFunc(r.list("users"), func(u map[string]any) bool { return u["username"] == "Bob[x]" }) {
		t.Fatalf("deleted user still listed: %s", users(r))
	}
	changed("role delete", func() {
		e.expect(e.api("DELETE", "/v1/admin/roles/"+djID, nil, bearer(ownerAT)), 204, "")
	})

	// Unrelated user updates don't bump it.
	before := version
	exec(`UPDATE users SET display_name = 'Dora', updated_at = now() WHERE username = 'dora'`)()
	e.expect(e.api("POST", "/v1/login", map[string]any{"login": "dora", "password": pw}), 200, "")
	if get().str("version") != before {
		t.Fatal("version bumped by an unrelated change")
	}
	// One bump per transaction, however many rows it touches.
	exec(`WITH x AS (UPDATE roles SET hoist = NOT hoist RETURNING 1) SELECT count(*) FROM x`)()
	var v1, v2 int64
	if err := sqldb.QueryRow(`SELECT version FROM irc_grants_version`).Scan(&v1); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE roles SET hoist = NOT hoist`)()
	if err := sqldb.QueryRow(`SELECT version FROM irc_grants_version`).Scan(&v2); err != nil {
		t.Fatal(err)
	}
	if v2 != v1+1 {
		t.Fatalf("multi-row statement bumped %d times", v2-v1)
	}
}
