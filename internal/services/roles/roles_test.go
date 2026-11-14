package roles

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/boson-chat/auth/internal/db/repositories/role"
	"github.com/boson-chat/auth/internal/perm"
)

func ptr[T any](v T) *T { return &v }

func mk(id, name string, pos int, builtin string, perms ...string) *role.Role {
	r := &role.Role{ID: id, Name: name, Slug: Slug(name), Position: pos, Permissions: perms}
	if builtin != "" {
		r.Builtin = &builtin
	}
	return r
}

var (
	owner  = mk(role.OwnerID, "Owner", 1000, role.BuiltinOwner)
	admin  = mk(role.AdminID, "Admin", 900, role.BuiltinAdmin, perm.Without(perm.RolesOwner)...)
	mod    = mk(role.ModeratorID, "Moderator", 500, role.BuiltinModerator, perm.UsersView, perm.UsersModerate, "irc.samode")
	member = mk(role.MemberID, "Member", 0, role.BuiltinMember, perm.ChannelCreate, perm.VoiceCreate)
	helper = mk("rol_helper", "Helper", 300, "", perm.UsersView)
)

func TestNames(t *testing.T) {
	for in, want := range map[string]string{"  Chat Helper ": "Chat Helper", "a": "a", "x_y-z 9": "x_y-z 9"} {
		if got, err := NormalizeName(in); err != nil || got != want {
			t.Errorf("NormalizeName(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "   ", strings.Repeat("a", 33), "émoji", "a.b", "tab\tname", "{x}"} {
		if _, err := NormalizeName(bad); err == nil {
			t.Errorf("NormalizeName(%q) accepted", bad)
		}
	}
	if Slug("Chat  Helper") != "chat--helper" || Slug("Mod_Team") != "mod_team" {
		t.Fatal("slug")
	}
	if c, err := NormalizeColor("#AbCdEf"); err != nil || c != "#abcdef" {
		t.Fatalf("color %q %v", c, err)
	}
	for _, bad := range []string{"abcdef", "#abc", "#abcdeg", "#abcdef0"} {
		if _, err := NormalizeColor(bad); err == nil {
			t.Errorf("color %q accepted", bad)
		}
	}
	if _, err := NormalizeWhoisLine("is a\x07 bell"); err == nil {
		t.Fatal("control char accepted")
	}
}

func TestVhostTemplates(t *testing.T) {
	for _, ok := range []string{"{username}.staff.boson.chat", "staff/{username}", "boson.chat", "{username}", "users/{username}/x_y",
		"{username}.{username}.s"} {
		if err := ValidateVhostTemplate(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"{username}.staff boson", "{user}.x", "{username}.ex@mple", ".staff", "staff.", "/staff", "staff/",
		"a..b", "a//b", "{username}." + strings.Repeat("x", 34), "{USERNAME}.x", ""} {
		if err := ValidateVhostTemplate(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := ValidateVhostTemplate("{username}." + strings.Repeat("x", 33)); err != nil {
		t.Errorf("64 bytes with a 30-char username must fit: %v", err)
	}
	for _, c := range []struct{ tmpl, user, want string }{
		{"{username}.staff.boson.chat", "Alice", "alice.staff.boson.chat"},
		{"staff/{username}", "[Bot]", "staff/-bot-"},
		{"{username}.x", "a\\b^c`d{e}f|g", "a-b-c-d-e-f-g.x"},
		{"{username}.x", "under_score-dash", "under_score-dash.x"},
		{"shared.vhost", "anyone", "shared.vhost"},
	} {
		if got := RenderVhost(c.tmpl, c.user); got != c.want {
			t.Errorf("RenderVhost(%q, %q) = %q, want %q", c.tmpl, c.user, got, c.want)
		}
		if !vhostRe.MatchString(RenderVhost(c.tmpl, c.user)) {
			t.Errorf("render not an Ergo vhost")
		}
	}
	if RenderVhost(strings.Repeat("a", 65), "x") != "" {
		t.Fatal("over-long render must be dropped")
	}
}

func TestApplyBuiltinRules(t *testing.T) {
	o := *owner
	if err := apply(&o, Input{Permissions: &[]string{}}); err == nil {
		t.Fatal("owner permissions editable")
	}
	if err := apply(&o, Input{Position: ptr(999)}); err == nil {
		t.Fatal("owner position editable")
	}
	if err := apply(&o, Input{Position: ptr(1000), Color: Some("#FFFFFF")}); err != nil || *o.Color != "#ffffff" {
		t.Fatalf("owner colour: %v", err)
	}
	m := *mod
	if err := apply(&m, Input{Name: ptr("Mods")}); err == nil {
		t.Fatal("builtin rename")
	}
	if err := apply(&m, Input{Name: ptr("Moderator"), Position: ptr(600)}); err != nil || m.Position != 600 {
		t.Fatalf("same name / move: %v", err)
	}
	c := *helper
	if err := apply(&c, Input{Position: ptr(0)}); err == nil {
		t.Fatal("position 0 accepted for a custom role")
	}
	err := apply(&c, Input{Name: ptr("New Name"), IRC: &IRCInput{WhoisLine: Some("  is helpful "), Vhost: Some("{username}.h.boson.chat"), Oper: ptr(true)}})
	if err != nil || c.Slug != "new-name" || *c.IRCWhoisLine != "is helpful" || *c.IRCVhost != "{username}.h.boson.chat" || !c.IRCOper {
		t.Fatalf("apply: %v %+v", err, c)
	}
	if err := apply(&c, Input{IRC: &IRCInput{WhoisLine: Some(""), Vhost: Nullable[string]{Set: true}}}); err != nil || c.IRCWhoisLine != nil || c.IRCVhost != nil {
		t.Fatalf("reset: %v %+v", err, c)
	}
}

func TestNullableJSON(t *testing.T) {
	var in Input
	if err := json.Unmarshal([]byte(`{"color":null,"irc":{"vhost":"x.y"}}`), &in); err != nil {
		t.Fatal(err)
	}
	if !in.Color.Set || in.Color.Value != nil || !in.IRC.Vhost.Set || *in.IRC.Vhost.Value != "x.y" || in.IRC.WhoisLine.Set || in.Name != nil {
		t.Fatalf("decoded %+v", in)
	}
	if !(Input{}).empty() || in.empty() {
		t.Fatal("empty")
	}
	if err := json.Unmarshal([]byte(`{"color":5}`), &in); err == nil {
		t.Fatal("wrong type accepted")
	}
}

func TestEffective(t *testing.T) {
	if len(EffectivePermissions(owner)) != len(perm.IDs()) || !EffectiveOper(owner) {
		t.Fatal("owner has everything")
	}
	if EffectiveOper(member) || EffectiveOper(helper) || !EffectiveOper(mod) {
		t.Fatal("oper derives from irc.* permissions")
	}
	h := *helper
	h.IRCOper = true
	if !EffectiveOper(&h) || len(IRCCapabilities(&h)) != 0 {
		t.Fatal("explicit oper")
	}
	if EffectiveWhoisLine(admin) != "is an Admin" || EffectiveWhoisLine(mod) != "is a Moderator" {
		t.Fatal("default whois")
	}
	if !slices.Equal(IRCCapabilities(mod), []string{"samode"}) {
		t.Fatal("caps")
	}
	colored := *helper
	colored.Color = ptr("#ff0000")
	if Visible(helper) || !Visible(&colored) || Visible(member) {
		t.Fatal("visible")
	}
}

func TestAccessAndHierarchy(t *testing.T) {
	a := NewAccess("usr_a", []*role.Role{admin, member})
	if a.Top != 900 || a.Owner || a.Has(perm.RolesOwner) || !a.Has(perm.RolesManage) || !a.HasAny(perm.RolesOwner, perm.AuditView) {
		t.Fatalf("admin access %+v", a)
	}
	if a.CanManageRole(admin) || a.CanManageRole(owner) || !a.CanManageRole(mod) || !a.CanManageRole(member) {
		t.Fatal("admin role management")
	}
	if a.CanPlaceAt(900) || !a.CanPlaceAt(899) {
		t.Fatal("placement")
	}
	if got := a.Missing([]string{perm.RolesOwner, perm.AdminPanel}); !slices.Equal(got, []string{perm.RolesOwner}) {
		t.Fatalf("missing %v", got)
	}
	m := NewAccess("usr_m", []*role.Role{mod, member})
	if !a.Outranks(m) || m.Outranks(a) || a.Outranks(a) {
		t.Fatal("outranks")
	}
	if names := NewAccess("u", []*role.Role{admin, mod, helper, member}).RoleNames(2); !slices.Equal(names, []string{"Admin", "Moderator"}) {
		t.Fatalf("names %v", names)
	}
	o := NewAccess("usr_o", []*role.Role{owner, member})
	if !o.Owner || !o.CanManageRole(owner) || !o.CanPlaceAt(1000) || o.Missing([]string{perm.RolesOwner}) != nil || !o.Outranks(NewAccess("x", []*role.Role{owner})) {
		t.Fatal("owner bypass")
	}
	heir := NewAccess("usr_h", []*role.Role{mk("rol_h", "Heir", 800, "", perm.RolesOwner, perm.RolesManage)})
	if !heir.CanManageRole(owner) || heir.CanManageRole(admin) {
		t.Fatal("roles.owner manages only the Owner role above")
	}
	plain := NewAccess("usr_p", []*role.Role{member})
	if plain.Top != 0 || plain.CanManageRole(member) || len(plain.Assigned()) != 0 || !slices.Equal(plain.Permissions, []string{perm.ChannelCreate, perm.VoiceCreate}) {
		t.Fatalf("member-only %+v", plain)
	}
	sys := SystemAccess()
	if !sys.Has(perm.RolesOwner) || !sys.CanManageRole(owner) {
		t.Fatal("system")
	}
}

func TestReorderPositions(t *testing.T) {
	for _, c := range []struct{ in, want []int }{
		{[]int{1, 1, 1}, []int{3, 2, 1}},
		{[]int{500, 900}, []int{900, 500}},
		{[]int{300, 10, 300}, []int{300, 299, 10}},
		{[]int{999, 999}, []int{999, 998}},
		{[]int{5}, []int{5}},
	} {
		if got := reorderPositions(c.in); !slices.Equal(got, c.want) {
			t.Errorf("reorderPositions(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestComputeIRC(t *testing.T) {
	staff := mk("rol_s", "Staff", 700, "", "irc.samode")
	staff.IRCVhost = ptr("{username}.staff.boson.chat")
	m := *member
	m.IRCVhost = ptr("users/{username}")
	info := ComputeIRC("Bob", []*role.Role{admin, staff, mod, &m})
	if *info.OperClass != "admin" || *info.WhoisLine != "is an Admin" || *info.Vhost != "bob.staff.boson.chat" {
		t.Fatalf("info %+v", info)
	}
	info = ComputeIRC("carl", []*role.Role{helper, &m})
	if info.OperClass != nil || info.WhoisLine != nil || *info.Vhost != "users/carl" {
		t.Fatalf("plain info %+v", info)
	}
	b, _ := json.Marshal(ComputeIRC("x", []*role.Role{member}))
	if string(b) != `{"oper_class":null,"whois_line":null,"vhost":null}` {
		t.Fatalf("json %s", b)
	}
}

func TestCursor(t *testing.T) {
	id := "usr_01JZZZZZZZZZZZZZZZZZZZZZZZ"
	if got, err := decodeCursor(encodeCursor(id)); err != nil || got != id {
		t.Fatalf("round trip %q %v", got, err)
	}
	for _, bad := range []string{"!!", encodeCursor("rol_x"), encodeCursor("usr_short")} {
		if _, err := decodeCursor(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// grantsRepo serves Grants from memory (other methods are unused).
type grantsRepo struct {
	role.RoleRepositoryImpl
	roles []*role.Role
	users []*role.UserRoles
	asked [][]string
}

func (g *grantsRepo) List(context.Context) ([]*role.Role, error)   { return g.roles, nil }
func (g *grantsRepo) GrantsVersion(context.Context) (int64, error) { return 7, nil }
func (g *grantsRepo) EnabledUsersWithRoles(_ context.Context, anyOf []string) ([]*role.UserRoles, error) {
	g.asked = append(g.asked, anyOf)
	var out []*role.UserRoles
	for _, u := range g.users {
		if anyOf == nil || slices.ContainsFunc(u.RoleIDs, func(id string) bool { return slices.Contains(anyOf, id) }) {
			out = append(out, u)
		}
	}
	return out, nil
}

func TestGrants(t *testing.T) {
	dj := mk("rol_dj", "DJ", 10, "", perm.VoiceCreate)
	dj.IRCVhost = ptr("dj/{username}")
	mem := *member
	repo := &grantsRepo{roles: []*role.Role{owner, admin, mod, helper, dj, &mem}, users: []*role.UserRoles{
		{Username: "alice", RoleIDs: []string{role.AdminID}},
		{Username: "Bob[x]", RoleIDs: []string{role.ModeratorID, "rol_dj"}},
		{Username: "carl", RoleIDs: []string{"rol_helper"}},
		{Username: "dave"},
	}}
	s := &RolesService{Roles: repo}
	version, gs, err := s.Grants(context.Background())
	if err != nil || version != "7" {
		t.Fatal(version, err)
	}
	str := func(gs []Grant) string {
		var out []string
		for _, g := range gs {
			v := func(p *string) string {
				if p == nil {
					return "-"
				}
				return *p
			}
			out = append(out, g.Username+":"+v(g.OperClass)+":"+v(g.WhoisLine)+":"+v(g.Vhost))
		}
		return strings.Join(out, " ")
	}
	// Only oper or vhost roles are asked for; helper (no irc) isn't.
	if got := str(gs); got != "alice:admin:is an Admin:- Bob[x]:moderator:is a Moderator:dj/bob-x-" {
		t.Fatalf("grants: %s", got)
	}
	if fmt.Sprint(repo.asked[0]) != "[rol_00000000000000000000000001 rol_00000000000000000000000002 rol_00000000000000000000000003 rol_dj]" {
		t.Fatalf("asked for %v", repo.asked[0])
	}
	// A vhost on Member: every enabled account.
	mem.IRCVhost = ptr("users/{username}")
	_, gs, _ = s.Grants(context.Background())
	if repo.asked[1] != nil || str(gs) != "alice:admin:is an Admin:users/alice Bob[x]:moderator:is a Moderator:dj/bob-x- carl:-:-:users/carl dave:-:-:users/dave" {
		t.Fatalf("member vhost: %s (asked %v)", str(gs), repo.asked[1])
	}
}
