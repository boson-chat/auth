package integration

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/boson-chat/auth/config"
	"github.com/golang-jwt/jwt/v5"
)

const (
	ownerRoleID  = "rol_00000000000000000000000001"
	adminRoleID  = "rol_00000000000000000000000002"
	modRoleID    = "rol_00000000000000000000000003"
	memberRoleID = "rol_00000000000000000000000004"
)

func (e *env) userID(at string) string {
	e.t.Helper()
	r := e.api("GET", "/v1/me", nil, bearer(at))
	e.expect(r, 200, "")
	return r.str("user", "id")
}

func (e *env) internalAPI(method, path string, body any, opts ...opt) resp {
	e.t.Helper()
	return e.do(e.internal, method, path, body, append(opts, header("X-Internal-Token", e.cfg.InternalConfig.APIToken))...)
}

func strs(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func ids(list []map[string]any) []string {
	out := make([]string, 0, len(list))
	for _, m := range list {
		out = append(out, m["id"].(string))
	}
	return out
}

func TestBuiltinRolesAndCatalog(t *testing.T) {
	e := newEnv(t)
	ownerAT := e.ownerToken("boss")
	e.registerVerified("pleb", "pleb@example.com")

	r := e.api("GET", "/v1/admin/roles", nil, bearer(ownerAT))
	e.expect(r, 200, "")
	rs := r.list("roles")
	if got := ids(rs); !slices.Equal(got, []string{ownerRoleID, adminRoleID, modRoleID, memberRoleID}) {
		t.Fatalf("roles order: %v", got)
	}
	owner, member := rs[0], rs[3]
	if owner["builtin"] != "owner" || owner["position"] != float64(1000) || owner["member_count"] != float64(1) ||
		owner["slug"] != "owner" || owner["irc"].(map[string]any)["oper"] != true {
		t.Fatalf("owner: %v", owner)
	}
	if member["member_count"] != float64(2) || member["irc"].(map[string]any)["oper"] != false ||
		fmt.Sprint(member["permissions"]) != "[channel.create voice.create]" {
		t.Fatalf("member: %v", member)
	}
	if mod := rs[2]; slices.Contains(strs(mod["permissions"]), "admin.panel") || !slices.Contains(strs(mod["permissions"]), "irc.samode") {
		t.Fatalf("moderator: %v", mod)
	}
	if slices.Contains(strs(rs[1]["permissions"]), "roles.owner") {
		t.Fatal("Admin must not hold roles.owner")
	}

	p := e.api("GET", "/v1/admin/permissions", nil, bearer(ownerAT))
	e.expect(p, 200, "")
	groups := map[string]int{}
	for _, x := range p.list("permissions") {
		groups[x["group"].(string)]++
		if x["label"] == "" || x["description"] == "" {
			t.Fatalf("permission without label: %v", x)
		}
	}
	if groups["admin"] != 13 || groups["network"] != 4 || groups["irc"] != 16 {
		t.Fatalf("catalog groups: %v", groups)
	}
	if len(strs(owner["permissions"])) != 33 {
		t.Fatalf("owner has %d permissions", len(strs(owner["permissions"])))
	}

	// Plain users can't see the admin role API; the public list needs no auth.
	userAT := e.login("pleb", pw).str("access_token")
	e.expect(e.api("GET", "/v1/admin/roles", nil, bearer(userAT)), 403, "forbidden")
	e.expect(e.api("GET", "/v1/admin/permissions", nil, bearer(userAT)), 403, "forbidden")
	e.expect(e.api("DELETE", "/v1/admin/roles/"+modRoleID, nil, bearer(ownerAT)), 409, "builtin_role")
	e.expect(e.api("DELETE", "/v1/admin/roles/rol_nope", nil, bearer(ownerAT)), 404, "not_found")
}

func TestRoleCRUDValidationAndAudit(t *testing.T) {
	e := newEnv(t)
	ownerAT := e.ownerToken("boss")

	bad := []map[string]any{
		{},
		{"name": ""},
		{"name": "way too long a role name for anyone ok"},
		{"name": "émoji"},
		{"name": "ok", "color": "red"},
		{"name": "ok", "position": 1000},
		{"name": "ok", "position": 0},
		{"name": "ok", "permissions": []string{"irc.kick"}},
		{"name": "ok", "irc": map[string]any{"vhost": "{username}.staff boson"}},
		{"name": "ok", "irc": map[string]any{"vhost": ".staff.boson.chat"}},
		{"name": "ok", "irc": map[string]any{"vhost": "{username}..boson.chat"}},
		{"name": "ok", "irc": map[string]any{"vhost": "{username}.{username}.a-very-long-staff-suffix.example"}},
		{"name": "ok", "irc": map[string]any{"vhost": "{user}.staff.boson.chat"}},
		{"name": "ok", "irc": map[string]any{"whois_line": strings.Repeat("x", 65)}},
	}
	for _, b := range bad {
		e.expect(e.api("POST", "/v1/admin/roles", b, bearer(ownerAT)), 400, "invalid_request")
	}

	r := e.api("POST", "/v1/admin/roles", map[string]any{
		"name": "Chat Helper", "color": "#1ABC9C", "position": 300, "hoist": true,
		"permissions": []string{"irc.samode", "users.view", "irc.samode"},
		"irc":         map[string]any{"vhost": "{username}.helpers.boson.chat"},
	}, bearer(ownerAT))
	e.expect(r, 201, "")
	role := r.body["role"].(map[string]any)
	id := role["id"].(string)
	irc := role["irc"].(map[string]any)
	if !strings.HasPrefix(id, "rol_") || role["slug"] != "chat-helper" || role["color"] != "#1abc9c" || role["builtin"] != nil ||
		fmt.Sprint(role["permissions"]) != "[users.view irc.samode]" || irc["oper"] != true || irc["whois_line"] != nil ||
		irc["vhost"] != "{username}.helpers.boson.chat" || role["mentionable"] != false || role["member_count"] != float64(0) {
		t.Fatalf("created: %s", r.raw)
	}

	// Names are unique case-insensitively, and so are their slugs.
	e.expect(e.api("POST", "/v1/admin/roles", map[string]any{"name": "chat helper"}, bearer(ownerAT)), 409, "role_name_taken")
	e.expect(e.api("POST", "/v1/admin/roles", map[string]any{"name": "chat-helper"}, bearer(ownerAT)), 409, "role_name_taken")
	e.expect(e.api("POST", "/v1/admin/roles", map[string]any{"name": "Moderator"}, bearer(ownerAT)), 409, "role_name_taken")

	// Default position 1, no permissions, not an oper.
	r = e.api("POST", "/v1/admin/roles", map[string]any{"name": "Supporter"}, bearer(ownerAT))
	e.expect(r, 201, "")
	sup := r.body["role"].(map[string]any)
	if sup["position"] != float64(1) || len(strs(sup["permissions"])) != 0 || sup["irc"].(map[string]any)["oper"] != false || sup["color"] != nil {
		t.Fatalf("defaults: %s", r.raw)
	}

	// Partial update: null resets, absent keeps; explicit oper without irc.* perms.
	r = e.api("PATCH", "/v1/admin/roles/"+id, map[string]any{
		"color": nil, "irc": map[string]any{"whois_line": "is a Chat Helper (ask me!)", "oper": false},
	}, bearer(ownerAT))
	e.expect(r, 200, "")
	role = r.body["role"].(map[string]any)
	if role["color"] != nil || role["name"] != "Chat Helper" || role["irc"].(map[string]any)["whois_line"] != "is a Chat Helper (ask me!)" ||
		role["irc"].(map[string]any)["oper"] != true || role["irc"].(map[string]any)["vhost"] != "{username}.helpers.boson.chat" {
		t.Fatalf("patched: %s", r.raw)
	}
	r = e.api("PATCH", "/v1/admin/roles/"+sup["id"].(string), map[string]any{"irc": map[string]any{"oper": true}, "name": "Supporters"}, bearer(ownerAT))
	e.expect(r, 200, "")
	if r.body["role"].(map[string]any)["irc"].(map[string]any)["oper"] != true || r.str("role", "slug") != "supporters" {
		t.Fatalf("explicit oper: %s", r.raw)
	}
	e.expect(e.api("PATCH", "/v1/admin/roles/"+id, map[string]any{}, bearer(ownerAT)), 400, "invalid_request")
	e.expect(e.api("PATCH", "/v1/admin/roles/"+id, map[string]any{"name": "Supporters"}, bearer(ownerAT)), 409, "role_name_taken")

	// Built-ins: no renames, fixed Owner/Member positions, fixed Owner perms;
	// colours, WHOIS lines and vhosts are editable.
	e.expect(e.api("PATCH", "/v1/admin/roles/"+modRoleID, map[string]any{"name": "Mods"}, bearer(ownerAT)), 400, "invalid_request")
	e.expect(e.api("PATCH", "/v1/admin/roles/"+ownerRoleID, map[string]any{"permissions": []string{}}, bearer(ownerAT)), 400, "invalid_request")
	e.expect(e.api("PATCH", "/v1/admin/roles/"+ownerRoleID, map[string]any{"position": 999}, bearer(ownerAT)), 400, "invalid_request")
	e.expect(e.api("PATCH", "/v1/admin/roles/"+memberRoleID, map[string]any{"position": 5}, bearer(ownerAT)), 400, "invalid_request")
	r = e.api("PATCH", "/v1/admin/roles/"+ownerRoleID, map[string]any{"color": "#000000", "irc": map[string]any{"whois_line": "runs the place"}}, bearer(ownerAT))
	e.expect(r, 200, "")
	if r.str("role", "color") != "#000000" || len(strs(r.body["role"].(map[string]any)["permissions"])) != 33 {
		t.Fatalf("owner patch: %s", r.raw)
	}

	// GET one role.
	g := e.api("GET", "/v1/admin/roles/"+id, nil, bearer(ownerAT))
	e.expect(g, 200, "")
	if g.str("role", "name") != "Chat Helper" {
		t.Fatalf("get: %s", g.raw)
	}

	// Delete: holders lose it; audit trail with old/new.
	uid := e.registerVerified("helper1", "helper1@example.com")
	e.expect(e.api("PUT", "/v1/admin/users/"+uid+"/roles", map[string]any{"role_ids": []string{id}}, bearer(ownerAT)), 200, "")
	e.expect(e.api("DELETE", "/v1/admin/roles/"+id, nil, bearer(ownerAT)), 204, "")
	e.expect(e.api("GET", "/v1/admin/roles/"+id, nil, bearer(ownerAT)), 404, "not_found")
	if rs := e.api("GET", "/v1/admin/users/"+uid, nil, bearer(ownerAT)).list("roles"); len(rs) != 0 {
		t.Fatalf("roles after delete: %v", rs)
	}

	a := e.api("GET", "/v1/admin/audit?event=role_created,role_updated,role_deleted&limit=50", nil, bearer(ownerAT))
	e.expect(a, 200, "")
	events := map[string]int{}
	for _, en := range a.list("entries") {
		events[en["event"].(string)]++
		meta := en["meta"].(map[string]any)
		if en["event"] == "role_updated" && meta["role_id"] == id {
			oldV, newV := meta["old"].(map[string]any), meta["new"].(map[string]any)
			if _, ok := newV["irc_whois_line"]; !ok || oldV["color"] != "#1abc9c" {
				t.Fatalf("role_updated meta: %v", meta)
			}
			if _, ok := newV["name"]; ok {
				t.Fatalf("unchanged field audited: %v", meta)
			}
		}
	}
	if events["role_created"] != 2 || events["role_updated"] != 3 || events["role_deleted"] != 1 {
		t.Fatalf("audit events: %v", events)
	}
}

func TestRoleHierarchy(t *testing.T) {
	e := newEnv(t)
	ownerAT := e.ownerToken("boss")
	adminAT := e.adminToken("second")
	adminID := e.userID(adminAT)
	ownerID := e.userID(ownerAT)
	modUID := e.registerVerified("mod", "mod@example.com")
	e.expect(e.api("PUT", "/v1/admin/users/"+modUID+"/roles", map[string]any{"role_ids": []string{modRoleID}}, bearer(ownerAT)), 200, "")
	modAT := e.login("mod", pw).str("access_token")
	plainUID := e.registerVerified("plain", "plain@example.com")

	// Moderators lack roles.manage and admin.panel.
	e.expect(e.api("POST", "/v1/admin/roles", map[string]any{"name": "X"}, bearer(modAT)), 403, "forbidden")
	e.expect(e.api("GET", "/v1/admin/roles", nil, bearer(modAT)), 403, "forbidden")

	// Admins work strictly below 900 and only with permissions they hold.
	e.expect(e.api("POST", "/v1/admin/roles", map[string]any{"name": "Co-Admin", "position": 900}, bearer(adminAT)), 403, "role_hierarchy")
	e.expect(e.api("POST", "/v1/admin/roles", map[string]any{"name": "Heir", "permissions": []string{"roles.owner"}}, bearer(adminAT)), 403, "permission_not_held")
	r := e.api("POST", "/v1/admin/roles", map[string]any{"name": "Helper", "position": 400, "permissions": []string{"irc.samode"}}, bearer(adminAT))
	e.expect(r, 201, "")
	helperID := r.str("role", "id")
	e.expect(e.api("PATCH", "/v1/admin/roles/"+helperID, map[string]any{"position": 950}, bearer(adminAT)), 403, "role_hierarchy")
	e.expect(e.api("PATCH", "/v1/admin/roles/"+helperID, map[string]any{"position": 899}, bearer(adminAT)), 200, "")
	e.expect(e.api("PATCH", "/v1/admin/roles/"+adminRoleID, map[string]any{"color": "#ffffff"}, bearer(adminAT)), 403, "role_hierarchy")
	e.expect(e.api("PATCH", "/v1/admin/roles/"+ownerRoleID, map[string]any{"color": "#ffffff"}, bearer(adminAT)), 403, "role_hierarchy")
	e.expect(e.api("PATCH", "/v1/admin/roles/"+modRoleID, map[string]any{"color": "#123456"}, bearer(adminAT)), 200, "")
	e.expect(e.api("PATCH", "/v1/admin/roles/"+memberRoleID, map[string]any{"irc": map[string]any{"vhost": "{username}.users.boson.chat"}}, bearer(adminAT)), 200, "")

	// Assigning: below you, to users below you.
	e.expect(e.api("PUT", "/v1/admin/users/"+plainUID+"/roles", map[string]any{"role_ids": []string{adminRoleID}}, bearer(adminAT)), 403, "role_hierarchy")
	e.expect(e.api("PUT", "/v1/admin/users/"+plainUID+"/roles", map[string]any{"role_ids": []string{ownerRoleID}}, bearer(adminAT)), 403, "role_hierarchy")
	e.expect(e.api("PUT", "/v1/admin/users/"+ownerID+"/roles", map[string]any{"role_ids": []string{ownerRoleID, helperID}}, bearer(adminAT)), 403, "role_hierarchy")
	e.expect(e.api("PUT", "/v1/admin/users/"+plainUID+"/roles", map[string]any{"role_ids": []string{"rol_01JZZZZZZZZZZZZZZZZZZZZZZZ"}}, bearer(adminAT)), 400, "invalid_request")
	e.expect(e.api("PUT", "/v1/admin/users/"+plainUID+"/roles", map[string]any{}, bearer(adminAT)), 400, "invalid_request")
	e.expect(e.api("PUT", "/v1/admin/users/usr_nope/roles", map[string]any{"role_ids": []string{}}, bearer(adminAT)), 404, "not_found")
	r = e.api("PUT", "/v1/admin/users/"+plainUID+"/roles", map[string]any{"role_ids": []string{helperID, modRoleID, memberRoleID}}, bearer(adminAT))
	e.expect(r, 200, "")
	if got := ids(r.list("roles")); !slices.Equal(got, []string{helperID, modRoleID}) {
		t.Fatalf("assigned (Member is implicit, most senior first): %v", got)
	}
	// Admins can manage themselves below their own rank (adding a lower role).
	e.expect(e.api("PUT", "/v1/admin/users/"+adminID+"/roles", map[string]any{"role_ids": []string{adminRoleID, helperID}}, bearer(adminAT)), 200, "")

	// Moderators can disable users below them but not admins.
	e.expect(e.api("POST", "/v1/admin/users/"+adminID+"/disable", nil, bearer(modAT)), 403, "role_hierarchy")
	e.expect(e.api("GET", "/v1/admin/users/"+adminID+"/sessions", nil, bearer(modAT)), 200, "")
	e.expect(e.api("POST", "/v1/admin/users/"+plainUID+"/disable", nil, bearer(modAT)), 403, "role_hierarchy") // plain is now Helper (899) > Moderator (500)
	e.expect(e.api("PUT", "/v1/admin/users/"+plainUID+"/roles", map[string]any{"role_ids": []string{}}, bearer(adminAT)), 200, "")
	e.expect(e.api("POST", "/v1/admin/users/"+plainUID+"/disable", nil, bearer(modAT)), 200, "")
	e.expect(e.api("POST", "/v1/admin/users/"+plainUID+"/enable", nil, bearer(modAT)), 200, "")
	e.expect(e.api("POST", "/v1/admin/users", map[string]any{"username": "nope"}, bearer(modAT)), 403, "forbidden") // users.manage
	e.expect(e.api("GET", "/v1/admin/audit", nil, bearer(modAT)), 200, "")
	e.expect(e.api("GET", "/v1/admin/invites", nil, bearer(modAT)), 200, "")
	e.expect(e.api("GET", "/v1/admin/settings", nil, bearer(modAT)), 403, "forbidden")
	e.expect(e.api("GET", "/v1/admin/sso/providers", nil, bearer(modAT)), 403, "forbidden")

	// Admins can't delete roles at or above themselves.
	e.expect(e.api("DELETE", "/v1/admin/roles/"+helperID, nil, bearer(adminAT)), 204, "")

	// The last Owner can't be removed; with two, one may step down.
	e.expect(e.api("PUT", "/v1/admin/users/"+ownerID+"/roles", map[string]any{"role_ids": []string{}}, bearer(ownerAT)), 409, "last_owner")
	e.expect(e.api("PUT", "/v1/admin/users/"+adminID+"/roles", map[string]any{"role_ids": []string{ownerRoleID}}, bearer(ownerAT)), 200, "")
	e.expect(e.api("PUT", "/v1/admin/users/"+ownerID+"/roles", map[string]any{"role_ids": []string{adminRoleID}}, bearer(ownerAT)), 200, "")
	if r := e.api("GET", "/v1/admin/roles/"+ownerRoleID, nil, bearer(adminAT)); r.body["role"].(map[string]any)["member_count"] != float64(1) {
		t.Fatalf("owners after transfer: %s", r.raw)
	}
	// The old owner (now Admin) is outranked by the new one.
	e.expect(e.api("POST", "/v1/admin/users/"+adminID+"/disable", nil, bearer(ownerAT)), 403, "role_hierarchy")

	// Audit: user_roles_changed with old/new.
	a := e.api("GET", "/v1/admin/audit?event=user_roles_changed&target="+ownerID, nil, bearer(adminAT))
	es := a.list("entries")
	if len(es) != 1 {
		t.Fatalf("user_roles_changed: %s", a.raw)
	}
	meta := es[0]["meta"].(map[string]any)
	if fmt.Sprint(meta["old"]) != "["+ownerRoleID+"]" || fmt.Sprint(meta["new"]) != "["+adminRoleID+"]" ||
		fmt.Sprint(meta["added"]) != "["+adminRoleID+"]" || fmt.Sprint(meta["removed"]) != "["+ownerRoleID+"]" {
		t.Fatalf("meta: %v", meta)
	}
}

func TestUserRolesInAPIAndTokens(t *testing.T) {
	e := newEnv(t)
	ownerAT := e.ownerToken("boss")
	uid := e.registerVerified("alice", "alice@example.com")

	// No roles: Member permissions only, role=user.
	at := e.login("alice", pw).str("access_token")
	me := e.api("GET", "/v1/me", nil, bearer(at))
	if len(me.list("roles")) != 0 || fmt.Sprint(me.body["permissions"]) != "[channel.create voice.create]" || me.str("user", "role") != "user" {
		t.Fatalf("me: %s", me.raw)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(at, claims); err != nil {
		t.Fatal(err)
	}
	if _, ok := claims["roles"]; ok || fmt.Sprint(claims["perms"]) != "[channel.create voice.create]" || claims["role"] != "user" {
		t.Fatalf("member claims: %v", claims)
	}

	// Moderator: permissions follow, but no admin.panel → still role=user.
	e.expect(e.api("PUT", "/v1/admin/users/"+uid+"/roles", map[string]any{"role_ids": []string{modRoleID}}, bearer(ownerAT)), 200, "")
	at = e.login("alice", pw).str("access_token")
	claims = jwt.MapClaims{}
	_, _, _ = jwt.NewParser().ParseUnverified(at, claims)
	if fmt.Sprint(claims["roles"]) != "[Moderator]" || claims["role"] != "user" || !slices.Contains(strs(claims["perms"]), "users.moderate") {
		t.Fatalf("moderator claims: %v", claims)
	}
	v := e.api("POST", "/v1/voice/token", nil, bearer(at))
	vc := jwt.MapClaims{}
	_, _, _ = jwt.NewParser().ParseUnverified(v.str("token"), vc)
	if vc["role"] != "moderator" || fmt.Sprint(vc["perms"]) != "[channel.create voice.create voice.manage_any voice.bypass_locks]" || fmt.Sprint(vc["roles"]) != "[Moderator]" {
		t.Fatalf("voice claims: %v", vc)
	}

	// A custom role with admin.panel makes the 1.x role admin (column and claim).
	r := e.api("POST", "/v1/admin/roles", map[string]any{"name": "Viewer", "position": 600, "permissions": []string{"admin.panel", "users.view"}, "color": "#00ff00"}, bearer(ownerAT))
	e.expect(r, 201, "")
	viewerID := r.str("role", "id")
	e.expect(e.api("PUT", "/v1/admin/users/"+uid+"/roles", map[string]any{"role_ids": []string{modRoleID, viewerID}}, bearer(ownerAT)), 200, "")
	u := e.api("GET", "/v1/admin/users/"+uid, nil, bearer(ownerAT))
	e.expect(u, 200, "")
	if u.str("user", "role") != "admin" || fmt.Sprint(ids(u.list("roles"))) != fmt.Sprint([]string{viewerID, modRoleID}) ||
		!slices.Contains(strs(u.body["permissions"]), "admin.panel") || u.list("roles")[0]["color"] != "#00ff00" {
		t.Fatalf("admin user view: %s", u.raw)
	}
	at = e.login("alice", pw).str("access_token")
	claims = jwt.MapClaims{}
	_, _, _ = jwt.NewParser().ParseUnverified(at, claims)
	if claims["role"] != "admin" || fmt.Sprint(claims["roles"]) != "[Viewer Moderator]" {
		t.Fatalf("viewer claims: %v", claims)
	}
	e.expect(e.api("GET", "/v1/admin/roles", nil, bearer(at)), 200, "")

	// Users list carries each user's roles.
	l := e.api("GET", "/v1/admin/users?q=alice", nil, bearer(ownerAT))
	if us := l.list("users"); len(us) != 1 || len(us[0]["roles"].([]any)) != 2 {
		t.Fatalf("list: %s", l.raw)
	}

	// Taking admin.panel off the role demotes holders' legacy role.
	e.expect(e.api("PATCH", "/v1/admin/roles/"+viewerID, map[string]any{"permissions": []string{"users.view"}}, bearer(ownerAT)), 200, "")
	if u := e.api("GET", "/v1/admin/users/"+uid, nil, bearer(ownerAT)); u.str("user", "role") != "user" {
		t.Fatalf("legacy role after edit: %s", u.raw)
	}
	e.expect(e.api("GET", "/v1/admin/roles", nil, bearer(at)), 403, "forbidden") // checked live, not from the token

	// Legacy PATCH {role}: admin adds Admin, user strips admin-panel roles.
	e.expect(e.api("PATCH", "/v1/admin/users/"+uid, map[string]any{"role": "admin"}, bearer(ownerAT)), 200, "")
	u = e.api("GET", "/v1/admin/users/"+uid, nil, bearer(ownerAT))
	if u.str("user", "role") != "admin" || !slices.Contains(ids(u.list("roles")), adminRoleID) {
		t.Fatalf("legacy admin: %s", u.raw)
	}
	e.expect(e.api("PATCH", "/v1/admin/users/"+uid, map[string]any{"role": "user"}, bearer(ownerAT)), 200, "")
	u = e.api("GET", "/v1/admin/users/"+uid, nil, bearer(ownerAT))
	if u.str("user", "role") != "user" || fmt.Sprint(ids(u.list("roles"))) != fmt.Sprint([]string{viewerID, modRoleID}) {
		t.Fatalf("legacy user: %s", u.raw)
	}
	e.expect(e.api("PATCH", "/v1/admin/users/"+uid, map[string]any{"role": "root"}, bearer(ownerAT)), 400, "invalid_request")

	// Member edits apply to everyone (and to the legacy mirror).
	e.expect(e.api("PATCH", "/v1/admin/roles/"+memberRoleID, map[string]any{"permissions": []string{"channel.create"}}, bearer(ownerAT)), 200, "")
	bob := e.registerVerified("bob", "bob@example.com")
	_ = bob
	if p := e.api("GET", "/v1/me", nil, bearer(e.login("bob", pw).str("access_token"))); fmt.Sprint(p.body["permissions"]) != "[channel.create]" {
		t.Fatalf("member perms: %s", p.raw)
	}
}

func TestRoleMembersAndReorder(t *testing.T) {
	e := newEnv(t)
	ownerAT := e.ownerToken("boss")
	var uids []string
	for i := range 5 {
		uids = append(uids, e.registerVerified(fmt.Sprintf("user%d", i), fmt.Sprintf("user%d@example.com", i)))
	}
	for _, uid := range uids[:3] {
		e.expect(e.api("PUT", "/v1/admin/users/"+uid+"/roles", map[string]any{"role_ids": []string{modRoleID}}, bearer(ownerAT)), 200, "")
	}

	var seen []string
	cursor := ""
	for page := 0; page < 5; page++ {
		r := e.api("GET", "/v1/admin/roles/"+modRoleID+"/members?limit=2&cursor="+cursor, nil, bearer(ownerAT))
		e.expect(r, 200, "")
		for _, u := range r.list("users") {
			if u["assigned_at"] == nil || u["assigned_by"] == nil || u["username"] == "" || u["email"] != nil {
				t.Fatalf("member row: %v", u)
			}
			seen = append(seen, u["id"].(string))
		}
		next, _ := r.body["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	if !slices.Equal(seen, uids[:3]) {
		t.Fatalf("members %v, want %v", seen, uids[:3])
	}
	all := e.api("GET", "/v1/admin/roles/"+memberRoleID+"/members?limit=200", nil, bearer(ownerAT))
	if us := all.list("users"); len(us) != 6 || us[0]["assigned_at"] != nil {
		t.Fatalf("member members: %s", all.raw)
	}
	e.expect(e.api("GET", "/v1/admin/roles/"+modRoleID+"/members?cursor=bad", nil, bearer(ownerAT)), 400, "invalid_request")

	// Reorder three roles that all sit at the default position 1.
	var custom []string
	for _, n := range []string{"A", "B", "C"} {
		custom = append(custom, e.api("POST", "/v1/admin/roles", map[string]any{"name": n}, bearer(ownerAT)).str("role", "id"))
	}
	r := e.api("POST", "/v1/admin/roles/reorder", map[string]any{"order": []string{custom[2], custom[0], custom[1]}}, bearer(ownerAT))
	e.expect(r, 200, "")
	pos := map[string]float64{}
	var order []string
	for _, ro := range r.list("roles") {
		pos[ro["id"].(string)] = ro["position"].(float64)
		order = append(order, ro["id"].(string))
	}
	if !(pos[custom[2]] > pos[custom[0]] && pos[custom[0]] > pos[custom[1]] && pos[custom[1]] >= 1) {
		t.Fatalf("positions: %v", pos)
	}
	if order[0] != ownerRoleID || order[len(order)-1] != memberRoleID {
		t.Fatalf("order: %v", order)
	}
	// Swap Moderator above Admin? Only Owners can; Admins can't move Admin.
	r = e.api("POST", "/v1/admin/roles/reorder", map[string]any{"order": []string{modRoleID, adminRoleID}}, bearer(ownerAT))
	e.expect(r, 200, "")
	if ids(r.list("roles"))[1] != modRoleID {
		t.Fatalf("swap: %v", ids(r.list("roles")))
	}
	adminAT := e.adminToken("admin2")
	e.expect(e.api("POST", "/v1/admin/roles/reorder", map[string]any{"order": []string{custom[1], custom[0]}}, bearer(adminAT)), 200, "")
	e.expect(e.api("POST", "/v1/admin/roles/reorder", map[string]any{"order": []string{adminRoleID, modRoleID}}, bearer(adminAT)), 403, "role_hierarchy")
	for _, bad := range []map[string]any{{"order": []string{}}, {"order": []string{ownerRoleID}}, {"order": []string{custom[0], custom[0]}}, {"order": []string{"rol_01JZZZZZZZZZZZZZZZZZZZZZZZ"}}} {
		e.expect(e.api("POST", "/v1/admin/roles/reorder", bad, bearer(ownerAT)), 400, "invalid_request")
	}
}

func TestPublicRoleEndpoints(t *testing.T) {
	e := newEnv(t)
	ownerAT := e.ownerToken("boss")
	uid := e.registerVerified("Al[i]ce", "alice@example.com")
	e.registerVerified("nobody", "nobody@example.com")
	r := e.api("POST", "/v1/admin/roles", map[string]any{"name": "Hidden", "position": 10}, bearer(ownerAT))
	hidden := r.str("role", "id")
	e.expect(e.api("PUT", "/v1/admin/users/"+uid+"/roles", map[string]any{"role_ids": []string{modRoleID, hidden}}, bearer(ownerAT)), 200, "")

	p := e.api("GET", "/v1/roles", nil)
	e.expect(p, 200, "")
	if len(p.list("roles")) != 5 || p.header.Get("ETag") == "" || !strings.Contains(p.header.Get("Cache-Control"), "max-age") {
		t.Fatalf("public roles: %s %v", p.raw, p.header)
	}
	if _, ok := p.list("roles")[0]["permissions"]; ok {
		t.Fatal("public roles must not expose permissions")
	}
	nm := e.api("GET", "/v1/roles", nil, header("If-None-Match", p.header.Get("ETag")))
	if nm.status != 304 {
		t.Fatalf("If-None-Match: %d", nm.status)
	}

	u := e.api("GET", "/v1/users/roles?username=al%7Bi%7Dce&username=boss,nobody&username=ghost", nil)
	e.expect(u, 200, "")
	users := u.body["users"].(map[string]any)
	if fmt.Sprint(users["al{i}ce"]) != "["+modRoleID+"]" || fmt.Sprint(users["boss"]) != "["+ownerRoleID+"]" ||
		fmt.Sprint(users["nobody"]) != "[]" || users["ghost"] != nil {
		t.Fatalf("user roles (hidden roles omitted, folded lookup): %s", u.raw)
	}
	e.expect(e.api("GET", "/v1/users/roles", nil), 400, "invalid_request")
	many := make([]string, 101)
	for i := range many {
		many[i] = fmt.Sprintf("u%d", i)
	}
	e.expect(e.api("GET", "/v1/users/roles?username="+strings.Join(many, ","), nil), 400, "invalid_request")
}

func TestPublicRoleEndpointsAreRateLimited(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.RateLimitConfig.PublicBurst, c.RateLimitConfig.PublicPerMinute = 2, 1 })
	e.expect(e.api("GET", "/v1/roles", nil), 200, "")
	e.expect(e.api("GET", "/v1/users/roles?username=x", nil), 200, "")
	r := e.api("GET", "/v1/roles", nil)
	e.expect(r, 429, "rate_limited")
	if r.header.Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
}

func TestInternalRolesAndIRC(t *testing.T) {
	e := newEnv(t)
	ownerAT := e.ownerToken("boss")
	uid := e.registerVerified("Bob[x]", "bob@example.com")
	e.registerVerified("carl", "carl@example.com")

	e.expect(e.do(e.internal, "GET", "/internal/v1/roles", nil), 401, "")
	r := e.internalAPI("GET", "/internal/v1/roles", nil)
	e.expect(r, 200, "")
	version := r.str("version")
	if version == "" || r.header.Get("ETag") != `"`+version+`"` {
		t.Fatalf("version: %s %v", r.raw, r.header)
	}
	rs := r.list("roles")
	mod := rs[2]["irc"].(map[string]any)
	if mod["oper_class"] != "moderator" || mod["whois_line"] != "is a Moderator" || mod["oper"] != true ||
		fmt.Sprint(mod["capabilities"]) != "[kill ban nofakelag vhosts sajoin samode history]" {
		t.Fatalf("moderator irc: %v", mod)
	}
	if ad := rs[1]["irc"].(map[string]any); ad["whois_line"] != "is an Admin" {
		t.Fatalf("admin whois: %v", ad)
	}
	if mem := rs[3]["irc"].(map[string]any); mem["oper_class"] != nil || mem["oper"] != false || len(mem["capabilities"].([]any)) != 0 {
		t.Fatalf("member irc: %v", mem)
	}
	if e.internalAPI("GET", "/internal/v1/roles", nil, header("If-None-Match", `"`+version+`"`)).status != 304 {
		t.Fatal("If-None-Match must give 304")
	}

	// Staff role with a vhost; a change bumps the version.
	sr := e.api("POST", "/v1/admin/roles", map[string]any{"name": "Staff", "position": 700, "permissions": []string{"irc.samode"},
		"irc": map[string]any{"vhost": "{username}.staff.boson.chat", "whois_line": "is boson staff"}}, bearer(ownerAT))
	e.expect(sr, 201, "")
	staffID := sr.str("role", "id")
	e.expect(e.api("PATCH", "/v1/admin/roles/"+memberRoleID, map[string]any{"irc": map[string]any{"vhost": "users/{username}"}}, bearer(ownerAT)), 200, "")
	r2 := e.internalAPI("GET", "/internal/v1/roles", nil, header("If-None-Match", `"`+version+`"`))
	e.expect(r2, 200, "")
	if r2.str("version") == version {
		t.Fatal("version unchanged after edits")
	}
	e.expect(e.api("PUT", "/v1/admin/users/"+uid+"/roles", map[string]any{"role_ids": []string{modRoleID, staffID}}, bearer(ownerAT)), 200, "")

	// verify-password returns the most senior oper role and vhost.
	v := e.internalAPI("POST", "/internal/v1/verify-password", map[string]string{"username": "bob[x]", "password": pw})
	e.expect(v, 200, "")
	irc := v.body["irc"].(map[string]any)
	if v.body["ok"] != true || irc["oper_class"] != "staff" || irc["whois_line"] != "is boson staff" || irc["vhost"] != "bob-x-.staff.boson.chat" ||
		fmt.Sprint(v.body["roles"]) != "[Staff Moderator]" || !slices.Contains(strs(v.body["permissions"]), "channel.create") {
		t.Fatalf("verify-password: %s", v.raw)
	}
	bad := e.internalAPI("POST", "/internal/v1/verify-password", map[string]string{"username": "bob[x]", "password": "wrong password!!"})
	if bad.body["ok"] != false || bad.body["irc"] != nil {
		t.Fatalf("failed verify must not carry irc: %s", bad.raw)
	}

	// Lookup by account (OAUTHBEARER / SSO logins).
	c := e.internalAPI("GET", "/internal/v1/users/CARL/irc", nil)
	e.expect(c, 200, "")
	irc = c.body["irc"].(map[string]any)
	if c.str("username") != "carl" || c.body["disabled"] != false || irc["oper_class"] != nil || irc["whois_line"] != nil || irc["vhost"] != "users/carl" {
		t.Fatalf("carl irc: %s", c.raw)
	}
	o := e.internalAPI("GET", "/internal/v1/users/boss/irc", nil)
	if o.body["irc"].(map[string]any)["oper_class"] != "owner" || o.body["irc"].(map[string]any)["vhost"] != "users/boss" {
		t.Fatalf("owner irc: %s", o.raw)
	}
	e.expect(e.internalAPI("GET", "/internal/v1/users/ghost/irc", nil), 404, "not_found")
	e.expect(e.do(e.internal, "GET", "/internal/v1/users/carl/irc", nil), 401, "")
	e.expect(e.api("GET", "/internal/v1/users/carl/irc", nil, header("X-Internal-Token", e.cfg.InternalConfig.APIToken)), 404, "")
}
