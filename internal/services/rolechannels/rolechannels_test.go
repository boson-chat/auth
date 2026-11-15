package rolechannels_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/role"
	"github.com/boson-chat/auth/internal/db/repositories/rolechannel"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/perm"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/services/rolechannels"
	"github.com/boson-chat/auth/internal/services/roles"
)

// ---- in-memory fakes -------------------------------------------------------

type world struct {
	mu         sync.Mutex
	roles      []*role.Role        // most senior first
	held       map[string][]string // user id → role ids
	users      map[string]*user.User
	channels   []*rolechannel.RoleChannel
	private    map[string]bool
	autojoined map[string][]string
	version    int64
}

func strp(s string) *string { return &s }

const (
	modsID = "rol_01JD0000000000000000000005"
	djID   = "rol_01JD0000000000000000000006"
	nopeID = "rol_01JD0000000000000000000009"
)

func newWorld() *world {
	mk := func(id, name string, pos int, builtin string, perms ...string) *role.Role {
		r := &role.Role{ID: id, Name: name, Slug: strings.ToLower(name), Position: pos, Permissions: perms}
		if builtin != "" {
			r.Builtin = strp(builtin)
		}
		return r
	}
	w := &world{
		roles: []*role.Role{
			mk(role.OwnerID, "Owner", 1000, role.BuiltinOwner),
			mk(role.AdminID, "Admin", 900, role.BuiltinAdmin, perm.AdminPanel, perm.RolesManage),
			mk(modsID, "Mods", 500, "", perm.RolesManage),
			mk(djID, "DJ", 100, ""),
			mk(role.MemberID, "Member", 0, role.BuiltinMember),
		},
		held: map[string][]string{}, users: map[string]*user.User{}, private: map[string]bool{}, autojoined: map[string][]string{},
	}
	return w
}

func (w *world) addUser(id, name string, roleIDs ...string) {
	w.users[id] = &user.User{ID: id, Username: name, UsernameFolded: nick.Fold(name)}
	w.held[id] = roleIDs
}

func (w *world) roleByID(id string) *role.Role {
	for _, r := range w.roles {
		if r.ID == id {
			return r
		}
	}
	return nil
}

type roleRepo struct {
	role.RoleRepositoryImpl // unused methods panic via nil interface
	w                       *world
}

func (r roleRepo) List(context.Context) ([]*role.Role, error) { return r.w.roles, nil }
func (r roleRepo) FindByID(_ context.Context, id string) (*role.Role, error) {
	if x := r.w.roleByID(id); x != nil {
		return x, nil
	}
	return nil, repositories.ErrNotFound
}
func (r roleRepo) Lock(context.Context) error { return nil }
func (r roleRepo) ForUser(_ context.Context, userID string) ([]*role.Role, error) {
	var out []*role.Role
	for _, x := range r.w.roles {
		if x.Is(role.BuiltinMember) || slices.Contains(r.w.held[userID], x.ID) {
			out = append(out, x)
		}
	}
	return out, nil
}
func (r roleRepo) GrantsVersion(context.Context) (int64, error) { return r.w.version, nil }

type userRepo struct {
	user.UserRepositoryImpl
	w *world
}

func (u userRepo) FindByUsernameFolded(_ context.Context, folded string) (*user.User, error) {
	for _, x := range u.w.users {
		if x.UsernameFolded == folded {
			return x, nil
		}
	}
	return nil, repositories.ErrNotFound
}

type chanRepo struct{ w *world }

func (c chanRepo) bump() { c.w.version++ }

func (c chanRepo) All(context.Context) ([]*rolechannel.RoleChannel, error) {
	out := slices.Clone(c.w.channels)
	slices.SortFunc(out, func(a, b *rolechannel.RoleChannel) int {
		return strings.Compare(a.RoleID+" "+a.Channel, b.RoleID+" "+b.Channel)
	})
	return out, nil
}
func (c chanRepo) ForRoles(_ context.Context, ids []string) ([]*rolechannel.RoleChannel, error) {
	var out []*rolechannel.RoleChannel
	for _, x := range c.w.channels {
		if slices.Contains(ids, x.RoleID) {
			cp := *x
			out = append(out, &cp)
		}
	}
	slices.SortFunc(out, func(a, b *rolechannel.RoleChannel) int { return strings.Compare(a.Channel, b.Channel) })
	return out, nil
}
func (c chanRepo) ReplaceForRole(_ context.Context, roleID string, list []*rolechannel.RoleChannel) error {
	c.w.channels = slices.DeleteFunc(c.w.channels, func(x *rolechannel.RoleChannel) bool { return x.RoleID == roleID })
	for _, x := range list {
		cp := *x
		c.w.channels = append(c.w.channels, &cp)
	}
	c.bump()
	return nil
}
func (c chanRepo) Private(context.Context) ([]*rolechannel.Access, error) {
	var out []*rolechannel.Access
	for ch, p := range c.w.private {
		if p {
			out = append(out, &rolechannel.Access{Channel: ch, Private: true})
		}
	}
	return out, nil
}
func (c chanRepo) ReplacePrivate(_ context.Context, channels []string, _ time.Time) error {
	c.w.private = map[string]bool{}
	for _, ch := range channels {
		c.w.private[ch] = true
	}
	c.bump()
	return nil
}
func (c chanRepo) EnabledHolders(_ context.Context, ids []string) ([]*rolechannel.Holder, error) {
	var out []*rolechannel.Holder
	for uid, rids := range c.w.held {
		u := c.w.users[uid]
		if u.Disabled() {
			continue
		}
		for _, rid := range rids {
			if slices.Contains(ids, rid) {
				out = append(out, &rolechannel.Holder{RoleID: rid, UserID: uid, Username: u.Username, UsernameFolded: u.UsernameFolded})
			}
		}
	}
	return out, nil
}
func (c chanRepo) Autojoined(_ context.Context, userID string) ([]string, error) {
	return slices.Clone(c.w.autojoined[userID]), nil
}
func (c chanRepo) RecordAutojoined(_ context.Context, userID string, channels, keep []string, _ time.Time) error {
	cur := slices.DeleteFunc(c.w.autojoined[userID], func(ch string) bool { return !slices.Contains(keep, ch) })
	for _, ch := range channels {
		if !slices.Contains(cur, ch) {
			cur = append(cur, ch)
		}
	}
	c.w.autojoined[userID] = cur
	return nil
}

type tx struct{}

func (tx) WithTx(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

type auditLog struct {
	audit.AuditServiceImpl
	mu     sync.Mutex
	events []string
	metas  []map[string]any
}

func (a *auditLog) Record(_ context.Context, userID, event string, meta map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, userID+":"+event)
	a.metas = append(a.metas, meta)
}

type fixture struct {
	w        *world
	svc      rolechannels.RoleChannelsServiceImpl
	audit    *auditLog
	settings rolechannels.Settings
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{w: newWorld(), audit: &auditLog{}, settings: rolechannels.Settings{Rejoin: config.RejoinLogin}}
	f.w.addUser("usr_admin", "Admin1", role.AdminID)
	f.w.addUser("usr_mod", "Moddy", modsID)
	f.w.addUser("usr_dj", "DJ[x]", djID)
	f.w.addUser("usr_both", "Both", modsID, djID)
	f.w.addUser("usr_plain", "plain")
	f.svc = rolechannels.NewRoleChannelsService(rolechannels.Deps{
		Channels: chanRepo{f.w}, Roles: roleRepo{w: f.w}, Users: userRepo{w: f.w}, Tx: tx{}, Audit: f.audit,
		Access: func(_ context.Context, uid string) (*roles.Access, error) {
			if uid == "" {
				return roles.SystemAccess(), nil
			}
			rs, _ := roleRepo{w: f.w}.ForUser(context.Background(), uid)
			return roles.NewAccess(uid, rs), nil
		},
		Settings: func() rolechannels.Settings { return f.settings },
	})
	return f
}

func yes() *bool { b := true; return &b }
func no() *bool  { b := false; return &b }

func codeOf(err error) string {
	if e, ok := apperr.As(err); ok {
		return e.Code
	}
	return fmt.Sprint(err)
}

// ---- tests -----------------------------------------------------------------

func TestNormalizeChannel(t *testing.T) {
	for in, want := range map[string]string{"#Staff": "#staff", "  #a  ": "#a", "#x[]|^-_.!": "#x[]|^-_.!", "#" + strings.Repeat("A", 63): "#" + strings.Repeat("a", 63)} {
		if got, err := rolechannels.NormalizeChannel(in); err != nil || got != want {
			t.Errorf("NormalizeChannel(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "#", "staff", "&staff", "#a b", "#a,b", "#é", "#a\x07", "#" + strings.Repeat("a", 64)} {
		if _, err := rolechannels.NormalizeChannel(bad); err == nil {
			t.Errorf("NormalizeChannel(%q) accepted", bad)
		}
	}
}

func TestSetForRole(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	id, list, err := f.svc.SetForRole(ctx, "usr_admin", modsID, []rolechannels.ChannelInput{{Channel: "#Staff"}, {Channel: "#mods", Autojoin: no()}})
	if err != nil || id != modsID {
		t.Fatal(id, err)
	}
	if fmt.Sprint(list) != "[{#mods false false} {#staff true false}]" {
		t.Fatalf("list %v", list)
	}
	if len(f.audit.events) != 1 || f.audit.events[0] != "usr_admin:"+audit.EventRoleChannelsUpdated ||
		fmt.Sprint(f.audit.metas[0]["added"]) != "[#staff #mods]" {
		t.Fatalf("audit %v %v", f.audit.events, f.audit.metas)
	}
	// unchanged: no audit entry
	if _, _, err := f.svc.SetForRole(ctx, "usr_admin", modsID, []rolechannels.ChannelInput{{Channel: "#staff"}, {Channel: "#MODS", Autojoin: no()}}); err != nil {
		t.Fatal(err)
	}
	if len(f.audit.events) != 1 {
		t.Fatalf("no-op change audited: %v", f.audit.events)
	}
	// everyone = Member
	id, _, err = f.svc.SetForRole(ctx, "usr_admin", "Everyone", []rolechannels.ChannelInput{{Channel: "#lobby"}})
	if err != nil || id != rolechannels.Everyone {
		t.Fatal(id, err)
	}
	if _, got, _ := f.svc.ForRole(ctx, "everyone"); fmt.Sprint(got) != "[{#lobby true false}]" {
		t.Fatalf("everyone %v", got)
	}

	for _, c := range []struct {
		actor, role string
		in          []rolechannels.ChannelInput
		code        string
	}{
		{"usr_plain", djID, nil, "forbidden"},
		{"usr_mod", modsID, nil, "role_hierarchy"}, // own role: not below
		{"usr_mod", role.AdminID, nil, "role_hierarchy"},
		{"usr_admin", nopeID, nil, "not_found"},
		{"usr_admin", "x", nil, "not_found"},
		{"usr_admin", djID, []rolechannels.ChannelInput{{Channel: "dj"}}, "invalid_request"},
		{"usr_admin", djID, []rolechannels.ChannelInput{{Channel: "#a"}, {Channel: "#A"}}, "invalid_request"},
	} {
		if _, _, err := f.svc.SetForRole(ctx, c.actor, c.role, c.in); codeOf(err) != c.code {
			t.Errorf("%s on %s: %v, want %s", c.actor, c.role, err, c.code)
		}
	}
	// a moderator can manage a role below theirs
	if _, _, err := f.svc.SetForRole(ctx, "usr_mod", djID, []rolechannels.ChannelInput{{Channel: "#dj"}}); err != nil {
		t.Fatal(err)
	}
	many := make([]rolechannels.ChannelInput, rolechannels.MaxRoleChannels+1)
	for i := range many {
		many[i].Channel = fmt.Sprintf("#c%d", i)
	}
	if _, _, err := f.svc.SetForRole(ctx, "usr_admin", djID, many); codeOf(err) != "invalid_request" {
		t.Fatalf("too many: %v", err)
	}
}

func TestAccessAndFeed(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	must := func(_ string, _ []rolechannels.RoleChannel, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(f.svc.SetForRole(ctx, "", modsID, []rolechannels.ChannelInput{{Channel: "#staff"}, {Channel: "#ops", Autojoin: no()}}))
	must(f.svc.SetForRole(ctx, "", djID, []rolechannels.ChannelInput{{Channel: "#staff"}, {Channel: "#music"}}))
	must(f.svc.SetForRole(ctx, "", "everyone", []rolechannels.ChannelInput{{Channel: "#lobby"}, {Channel: "#members"}}))

	if _, err := f.svc.SetAccess(ctx, "usr_plain", nil); codeOf(err) != "forbidden" {
		t.Fatalf("plain user: %v", err)
	}
	v0, _ := f.svc.FeedVersion(ctx)
	access, err := f.svc.SetAccess(ctx, "usr_admin", []rolechannels.AccessInput{
		{Channel: "#Staff", Private: true}, {Channel: "#members", Private: true}, {Channel: "#secret", Private: true}, {Channel: "#music"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range access {
		var rs []string
		for _, r := range a.Roles {
			rs = append(rs, r.Name)
		}
		got = append(got, fmt.Sprintf("%s:%v:%v", a.Channel, a.Private, rs))
	}
	if want := "[#lobby:false:[Everyone] #members:true:[Everyone] #music:false:[DJ] #ops:false:[Mods] #secret:true:[] #staff:true:[Mods DJ]]"; fmt.Sprint(got) != want {
		t.Fatalf("access\n got %v\nwant %s", got, want)
	}
	if ev := f.audit.events[len(f.audit.events)-1]; ev != "usr_admin:"+audit.EventChannelAccessUpdated {
		t.Fatalf("audit %v", ev)
	}

	v1, _ := f.svc.FeedVersion(ctx)
	if v1 == v0 {
		t.Fatal("version not bumped")
	}
	f.settings.Autojoin = true
	if v2, _ := f.svc.FeedVersion(ctx); v2 == v1 {
		t.Fatal("settings change must change the version")
	}

	feed, err := f.svc.Feed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !feed.Autojoin || feed.Rejoin != "login" {
		t.Fatalf("settings %+v", feed)
	}
	byName := map[string]rolechannels.FeedChannel{}
	for _, c := range feed.Channels {
		byName[c.Channel] = c
	}
	if c := byName["#staff"]; !c.Private || c.Everyone || fmt.Sprint(c.Accounts) != "[both dj[x] moddy]" {
		t.Fatalf("#staff %+v", c)
	}
	if c := byName["#members"]; !c.Private || !c.Everyone || len(c.Accounts) != 0 {
		t.Fatalf("#members %+v", c)
	}
	if c := byName["#secret"]; !c.Private || len(c.Accounts) != 0 {
		t.Fatalf("#secret %+v", c)
	}
	if c := byName["#music"]; c.Private || len(c.Accounts) != 0 {
		t.Fatalf("#music %+v", c)
	}
	// a disabled account drops out
	now := time.Now()
	f.w.users["usr_dj"].DisabledAt = &now
	feed, _ = f.svc.Feed(ctx)
	for _, c := range feed.Channels {
		if c.Channel == "#staff" && fmt.Sprint(c.Accounts) != "[both moddy]" {
			t.Fatalf("disabled account still listed: %v", c.Accounts)
		}
	}

	// public again
	if _, err := f.svc.SetAccess(ctx, "usr_admin", []rolechannels.AccessInput{{Channel: "#a", Private: true}, {Channel: "#a"}}); codeOf(err) != "invalid_request" {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := f.svc.SetAccess(ctx, "usr_admin", nil); err != nil {
		t.Fatal(err)
	}
	if meta := f.audit.metas[len(f.audit.metas)-1]; fmt.Sprint(meta["made_public"]) != "[#members #secret #staff]" {
		t.Fatalf("made_public %v", meta)
	}
}

func TestAutojoinOnceAndMine(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.svc.SetForRole(ctx, "", modsID, []rolechannels.ChannelInput{{Channel: "#staff"}, {Channel: "#ops", Autojoin: no()}})
	f.svc.SetForRole(ctx, "", djID, []rolechannels.ChannelInput{{Channel: "#staff"}, {Channel: "#music"}})
	f.svc.SetForRole(ctx, "", "everyone", []rolechannels.ChannelInput{{Channel: "#lobby"}})
	f.svc.SetAccess(ctx, "", []rolechannels.AccessInput{{Channel: "#staff", Private: true}})
	f.settings = rolechannels.Settings{Autojoin: true, Rejoin: config.RejoinOnce}

	aj, err := f.svc.Autojoin(ctx, "BOTH")
	if err != nil {
		t.Fatal(err)
	}
	if aj.Account != "Both" || !aj.Enabled || aj.Rejoin != "once" || fmt.Sprint(aj.Channels) != "[#lobby #music #staff]" ||
		fmt.Sprint(aj.Pending) != "[#lobby #music #staff]" {
		t.Fatalf("autojoin %+v", aj)
	}
	// RFC 1459 folding finds DJ[x] as dj{x}
	if aj, err := f.svc.Autojoin(ctx, "dj{X}"); err != nil || fmt.Sprint(aj.Channels) != "[#lobby #music #staff]" {
		t.Fatalf("dj %+v %v", aj, err)
	}
	if _, err := f.svc.Autojoin(ctx, "ghost"); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("ghost: %v", err)
	}

	// joined two; #ops (autojoin off) and #nope aren't recorded
	aj, err = f.svc.RecordAutojoined(ctx, "both", []string{"#Lobby", "#staff", "#ops", "#nope"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(aj.Pending) != "[#music]" || fmt.Sprint(f.w.autojoined["usr_both"]) != "[#lobby #staff]" {
		t.Fatalf("after record %+v %v", aj, f.w.autojoined["usr_both"])
	}
	if _, err := f.svc.RecordAutojoined(ctx, "both", []string{"bad"}); codeOf(err) != "invalid_request" {
		t.Fatalf("bad channel: %v", err)
	}
	// losing DJ prunes nothing yet (#staff is still Mods'); losing Mods too drops #staff
	f.w.held["usr_both"] = nil
	aj, _ = f.svc.RecordAutojoined(ctx, "both", nil)
	if fmt.Sprint(f.w.autojoined["usr_both"]) != "[#lobby]" || fmt.Sprint(aj.Pending) != "[]" {
		t.Fatalf("prune %v %+v", f.w.autojoined["usr_both"], aj)
	}
	// regaining it makes it pending again
	f.w.held["usr_both"] = []string{modsID}
	if aj, _ := f.svc.Autojoin(ctx, "both"); fmt.Sprint(aj.Pending) != "[#staff]" {
		t.Fatalf("regain %+v", aj)
	}

	// a disabled account gets nothing
	now := time.Now()
	f.w.users["usr_mod"].DisabledAt = &now
	if aj, _ := f.svc.Autojoin(ctx, "moddy"); len(aj.Channels) != 0 {
		t.Fatalf("disabled %+v", aj)
	}

	mine, err := f.svc.ForUser(ctx, "usr_dj")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(mine) != "[{#lobby false true [Everyone]} {#music false true [DJ]} {#staff true true [DJ]}]" {
		t.Fatalf("mine %v", mine)
	}
	f.w.held["usr_dj"] = []string{modsID, djID}
	mine, _ = f.svc.ForUser(ctx, "usr_dj")
	if fmt.Sprint(mine) != "[{#lobby false true [Everyone]} {#music false true [DJ]} {#ops false false [Mods]} {#staff true true [Mods DJ]}]" {
		t.Fatalf("mine with Mods %v", mine)
	}
}

func TestSettingsDefault(t *testing.T) {
	w := newWorld()
	svc := rolechannels.NewRoleChannelsService(rolechannels.Deps{Channels: chanRepo{w}, Roles: roleRepo{w: w}, Users: userRepo{w: w},
		Settings: func() rolechannels.Settings { return rolechannels.Settings{} }})
	feed, err := svc.Feed(context.Background())
	if err != nil || feed.Autojoin || feed.Rejoin != "login" || len(feed.Channels) != 0 {
		t.Fatalf("%+v %v", feed, err)
	}
}
