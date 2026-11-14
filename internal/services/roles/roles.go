// Package roles manages network roles: built-in (Owner, Admin, Moderator,
// Member) and custom ones, their permissions, IRC oper class and vhost, and
// who holds them.
//
// Hierarchy (Discord rule): an actor may only create, edit, delete, assign
// or remove roles positioned strictly below their own highest role, act on
// users whose highest role is below theirs, and grant only permissions they
// hold. Owners bypass all of it; roles.owner lets a non-Owner manage the
// Owner role itself. There is always at least one Owner.
package roles

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	nethttp "net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/role"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/perm"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/textutil"
)

const (
	MaxPageSize = 200
	// MaxLookupUsernames bounds GET /v1/users/roles.
	MaxLookupUsernames = 100
	// MaxTokenRoles bounds the roles claim.
	MaxTokenRoles = 20
	maxAssign     = 100
)

var (
	ErrHierarchy = apperr.New(nethttp.StatusForbidden, "role_hierarchy", "you can only manage roles and users below your highest role")
	ErrBuiltin   = apperr.New(nethttp.StatusConflict, "builtin_role", "built-in roles can't be deleted")
	ErrNameTaken = apperr.New(nethttp.StatusConflict, "role_name_taken", "a role with that name already exists")
	ErrLastOwner = apperr.New(nethttp.StatusConflict, "last_owner", "the network must keep at least one Owner")
	// ErrStale is If-Match: <updated_at> not matching the role any more.
	ErrStale  = apperr.New(nethttp.StatusPreconditionFailed, "precondition_failed", "the role changed since you read it")
	errCursor = apperr.Invalid("invalid cursor")
)

func errNotHeld(missing []string) error {
	return apperr.New(nethttp.StatusForbidden, "permission_not_held", "you can't grant permissions you don't hold: "+strings.Join(missing, ", "))
}

// EffectivePermissions is what holding r grants: every permission for Owner.
func EffectivePermissions(r *role.Role) []string {
	if r.Is(role.BuiltinOwner) {
		return perm.IDs()
	}
	return perm.Sort(r.Permissions)
}

// EffectiveOper reports whether holders of r are IRC opers: set explicitly
// or implied by any irc.* permission.
func EffectiveOper(r *role.Role) bool {
	if r.IRCOper {
		return true
	}
	return slices.ContainsFunc(EffectivePermissions(r), perm.IsIRC)
}

// EffectiveWhoisLine is the WHOIS line, defaulting to "is a(n) <name>".
func EffectiveWhoisLine(r *role.Role) string {
	if r.IRCWhoisLine != nil {
		return *r.IRCWhoisLine
	}
	article := "a"
	if r.Name != "" && strings.ContainsRune("AEIOUaeiou", rune(r.Name[0])) {
		article = "an"
	}
	return "is " + article + " " + r.Name
}

// IRCCapabilities are the Ergo oper capabilities r grants.
func IRCCapabilities(r *role.Role) []string {
	out := []string{}
	for _, p := range perm.Filter(EffectivePermissions(r), perm.GroupIRC) {
		out = append(out, perm.IRCCapability(p))
	}
	return out
}

// Visible reports whether r shows up for clients next to usernames (badges,
// colours): not Member, and hoisted or coloured.
func Visible(r *role.Role) bool {
	return !r.Is(role.BuiltinMember) && (r.Hoist || r.Color != nil)
}

// Access is what one user may do: their roles and effective permissions.
type Access struct {
	UserID string
	// Roles are the stored roles plus Member, most senior first.
	Roles       []*role.Role
	Permissions []string
	// Top is the position of the most senior role (0 = Member only).
	Top   int
	Owner bool
	// System is the CLI / internal actor: everything allowed.
	System bool
	set    map[string]bool
}

// SystemAccess is the access of actorID "" (CLI).
func SystemAccess() *Access {
	return &Access{System: true, Owner: true, Top: role.OwnerPosition + 1, Permissions: perm.IDs(), set: map[string]bool{}}
}

// NewAccess computes the access granted by roles (sorted most senior first).
func NewAccess(userID string, roles []*role.Role) *Access {
	a := &Access{UserID: userID, Roles: roles, set: map[string]bool{}}
	for _, r := range roles {
		if r.Is(role.BuiltinOwner) {
			a.Owner = true
		}
		if r.Position > a.Top {
			a.Top = r.Position
		}
		for _, p := range EffectivePermissions(r) {
			a.set[p] = true
		}
	}
	ps := make([]string, 0, len(a.set))
	for p := range a.set {
		ps = append(ps, p)
	}
	a.Permissions = perm.Sort(ps)
	return a
}

func (a *Access) Has(p string) bool { return a.System || a.set[p] }

// HasAny reports whether a holds at least one of ps.
func (a *Access) HasAny(ps ...string) bool { return slices.ContainsFunc(ps, a.Has) }

// Assigned is the stored roles (without Member).
func (a *Access) Assigned() []*role.Role {
	out := []*role.Role{}
	for _, r := range a.Roles {
		if !r.Is(role.BuiltinMember) {
			out = append(out, r)
		}
	}
	return out
}

// RoleNames is the names of the assigned roles, most senior first, at most n.
func (a *Access) RoleNames(n int) []string {
	out := []string{}
	for _, r := range a.Assigned() {
		if len(out) == n {
			break
		}
		out = append(out, r.Name)
	}
	return out
}

func (a *Access) bypass() bool { return a.System || a.Owner }

// CanManageRole: strictly below the actor's top role; the Owner role needs
// Owner or roles.owner.
func (a *Access) CanManageRole(r *role.Role) bool {
	if a.bypass() {
		return true
	}
	if r.Is(role.BuiltinOwner) {
		return a.Has(perm.RolesOwner)
	}
	return r.Position < a.Top
}

// CanPlaceAt reports whether the actor may put a role at position p.
func (a *Access) CanPlaceAt(p int) bool { return a.bypass() || p < a.Top }

// Outranks reports whether the actor may act on a user with access t.
func (a *Access) Outranks(t *Access) bool { return a.bypass() || t.Top < a.Top }

// Missing returns the permissions in ps the actor doesn't hold.
func (a *Access) Missing(ps []string) []string {
	if a.bypass() {
		return nil
	}
	var out []string
	for _, p := range ps {
		if !a.set[p] {
			out = append(out, p)
		}
	}
	return out
}

// View is a role with its holder count.
type View struct {
	*role.Role
	MemberCount int64
}

// IRCInfo is what Ergo applies at login: the oper class of the most senior
// oper role and the vhost of the most senior role with a vhost template.
type IRCInfo struct {
	OperClass *string `json:"oper_class"`
	WhoisLine *string `json:"whois_line"`
	Vhost     *string `json:"vhost"`
}

// ComputeIRC derives IRCInfo from roles sorted most senior first.
func ComputeIRC(username string, roles []*role.Role) IRCInfo {
	var out IRCInfo
	for _, r := range roles {
		if out.OperClass == nil && EffectiveOper(r) {
			slug, whois := r.Slug, EffectiveWhoisLine(r)
			out.OperClass, out.WhoisLine = &slug, &whois
		}
		if out.Vhost == nil && r.IRCVhost != nil {
			if v := RenderVhost(*r.IRCVhost, username); v != "" {
				out.Vhost = &v
			}
		}
	}
	return out
}

// Member is one row of GET /v1/admin/roles/{id}/members.
type Member = role.Member

type RolesServiceImpl interface {
	// List returns every role with member counts, most senior first.
	List(ctx context.Context) ([]*View, error)
	Create(ctx context.Context, actorID string, in Input) (*View, error)
	Update(ctx context.Context, actorID, id string, in Input) (*View, error)
	Delete(ctx context.Context, actorID, id string) error
	// Reorder gives the listed roles (most senior first) new positions.
	Reorder(ctx context.Context, actorID string, order []string) ([]*View, error)
	// Members pages through a role's holders by user id.
	Members(ctx context.Context, id, cursor string, limit int) ([]*Member, string, error)

	// Access is userID's roles and permissions; "" is the system actor.
	Access(ctx context.Context, userID string) (*Access, error)
	// AssignedForUsers returns each user's stored roles, most senior first.
	AssignedForUsers(ctx context.Context, userIDs []string) (map[string][]*role.Role, error)
	// SetUserRoles replaces userID's stored roles (Member ids are ignored).
	SetUserRoles(ctx context.Context, actorID, userID string, roleIDs []string) ([]*role.Role, error)
	// SetLegacyRole maps the 1.x role field: user = drop every admin.panel
	// role, admin = add Admin (unless already admin.panel), owner = add Owner.
	SetLegacyRole(ctx context.Context, actorID, userID, legacy string) error
	// CheckAssign fails unless actorID may give a new user the built-in role.
	CheckAssign(ctx context.Context, actorID, roleID string) error
	// CheckManageUser fails unless actorID outranks targetID (or is targetID).
	CheckManageUser(ctx context.Context, actorID, targetID string) error

	// Version is a hash of every role, for ETags and pollers.
	Version(ctx context.Context) ([]*role.Role, string, error)
	// PublicUserRoles maps each requested username that exists to the ids of
	// its visible roles.
	PublicUserRoles(ctx context.Context, usernames []string) (map[string][]string, error)
	// IRCByUsername looks a user up by account name for Ergo.
	IRCByUsername(ctx context.Context, username string) (*user.User, IRCInfo, *Access, error)
	// IRC is userID's IRC login info.
	IRC(ctx context.Context, u *user.User) (IRCInfo, *Access, error)
	// GrantsVersion changes whenever any user's IRCInfo may have changed.
	GrantsVersion(ctx context.Context) (string, error)
	// Grants is every enabled user whose IRCInfo has an oper class or a
	// vhost, by folded username, with the GrantsVersion it is at least as
	// new as.
	Grants(ctx context.Context) (string, []Grant, error)
}

// Grant is one entry of GET /internal/v1/irc/grants.
type Grant struct {
	Username string
	IRCInfo
}

type RolesService struct {
	Roles role.RoleRepositoryImpl
	Users user.UserRepositoryImpl
	Tx    db.TxManagerImpl
	Audit audit.AuditServiceImpl
	Now   func() time.Time
}

func NewRolesService(roles role.RoleRepositoryImpl, users user.UserRepositoryImpl, tx db.TxManagerImpl, auditSvc audit.AuditServiceImpl, now func() time.Time) RolesServiceImpl {
	if now == nil {
		now = time.Now
	}
	return &RolesService{Roles: roles, Users: users, Tx: tx, Audit: auditSvc, Now: now}
}

// now is the current time at the database's (microsecond) precision, so a
// role's updated_at reads back exactly as written (If-Match compares it).
func (s *RolesService) now() time.Time { return s.Now().UTC().Truncate(time.Microsecond) }

func notFound(err error) error {
	if errors.Is(err, repositories.ErrNotFound) {
		return apperr.ErrNotFound
	}
	return err
}

func validID(id string) bool { return textutil.Storable(id) && ids.HasPrefix(id, ids.Role) }

func (s *RolesService) find(ctx context.Context, id string) (*role.Role, error) {
	if !validID(id) {
		return nil, apperr.ErrNotFound
	}
	r, err := s.Roles.FindByID(ctx, id)
	return r, notFound(err)
}

func (s *RolesService) Access(ctx context.Context, userID string) (*Access, error) {
	if userID == "" {
		return SystemAccess(), nil
	}
	rs, err := s.Roles.ForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return NewAccess(userID, rs), nil
}

func (s *RolesService) withCounts(ctx context.Context, rs []*role.Role) ([]*View, error) {
	counts, err := s.Roles.MemberCounts(ctx)
	if err != nil {
		return nil, err
	}
	var total int64 = -1
	out := make([]*View, 0, len(rs))
	for _, r := range rs {
		n := counts[r.ID]
		if r.Is(role.BuiltinMember) {
			if total < 0 {
				if total, err = s.Roles.CountUsers(ctx); err != nil {
					return nil, err
				}
			}
			n = total
		}
		out = append(out, &View{Role: r, MemberCount: n})
	}
	return out, nil
}

func (s *RolesService) List(ctx context.Context) ([]*View, error) {
	rs, err := s.Roles.List(ctx)
	if err != nil {
		return nil, err
	}
	return s.withCounts(ctx, rs)
}

func (s *RolesService) view(ctx context.Context, r *role.Role) (*View, error) {
	vs, err := s.withCounts(ctx, []*role.Role{r})
	if err != nil {
		return nil, err
	}
	return vs[0], nil
}

// snapshot is the audited form of a role.
func snapshot(r *role.Role) map[string]any {
	return map[string]any{
		"name": r.Name, "color": r.Color, "position": r.Position, "permissions": EffectivePermissions(r),
		"irc_whois_line": r.IRCWhoisLine, "irc_vhost": r.IRCVhost, "irc_oper": EffectiveOper(r),
		"hoist": r.Hoist, "mentionable": r.Mentionable,
	}
}

// diff returns the changed fields' old and new values.
func diff(a, b map[string]any) (map[string]any, map[string]any) {
	oldV, newV := map[string]any{}, map[string]any{}
	for k, x := range a {
		xj, _ := json.Marshal(x)
		yj, _ := json.Marshal(b[k])
		if string(xj) != string(yj) {
			oldV[k], newV[k] = x, b[k]
		}
	}
	return oldV, newV
}

func (s *RolesService) actor(ctx context.Context, actorID string) (*Access, error) {
	a, err := s.Access(ctx, actorID)
	if err != nil {
		return nil, err
	}
	if !a.Has(perm.RolesManage) {
		return nil, apperr.ErrForbidden
	}
	return a, nil
}

func (s *RolesService) Create(ctx context.Context, actorID string, in Input) (*View, error) {
	if in.Name == nil {
		return nil, apperr.Invalid("name is required")
	}
	now := s.now()
	r := &role.Role{ID: ids.New(ids.Role), Position: MinPosition, Permissions: []string{}, CreatedAt: now, UpdatedAt: now}
	if err := apply(r, in); err != nil {
		return nil, err
	}
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.Roles.Lock(ctx); err != nil {
			return err
		}
		a, err := s.actor(ctx, actorID)
		if err != nil {
			return err
		}
		if !a.CanPlaceAt(r.Position) {
			return ErrHierarchy
		}
		if missing := a.Missing(r.Permissions); len(missing) > 0 {
			return errNotHeld(missing)
		}
		if err := s.Roles.Create(ctx, r); err != nil {
			if errors.Is(err, role.ErrNameTaken) {
				return ErrNameTaken
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.Audit.Record(ctx, actorID, audit.EventRoleCreated, map[string]any{"role_id": r.ID, "role": snapshot(r)})
	return &View{Role: r}, nil
}

func (s *RolesService) Update(ctx context.Context, actorID, id string, in Input) (*View, error) {
	if in.empty() {
		return nil, apperr.Invalid("nothing to update")
	}
	var r *role.Role
	var before, after map[string]any
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.Roles.Lock(ctx); err != nil {
			return err
		}
		var err error
		if r, err = s.find(ctx, id); err != nil {
			return err
		}
		a, err := s.actor(ctx, actorID)
		if err != nil {
			return err
		}
		if !a.CanManageRole(r) {
			return ErrHierarchy
		}
		if in.IfMatch != nil && !in.IfMatch.Truncate(time.Microsecond).Equal(r.UpdatedAt.Truncate(time.Microsecond)) {
			return ErrStale
		}
		before = snapshot(r)
		oldPos, oldPerms := r.Position, EffectivePermissions(r)
		if err := apply(r, in); err != nil {
			return err
		}
		if r.Position != oldPos && !a.CanPlaceAt(r.Position) {
			return ErrHierarchy
		}
		newPerms := EffectivePermissions(r)
		var added []string
		for _, p := range newPerms {
			if !slices.Contains(oldPerms, p) {
				added = append(added, p)
			}
		}
		if missing := a.Missing(added); len(missing) > 0 {
			return errNotHeld(missing)
		}
		r.UpdatedAt = s.now()
		if err := s.Roles.Save(ctx, r); err != nil {
			if errors.Is(err, role.ErrNameTaken) {
				return ErrNameTaken
			}
			return notFound(err)
		}
		after = snapshot(r)
		if !slices.Equal(oldPerms, newPerms) {
			return s.syncHolders(ctx, r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if oldV, newV := diff(before, after); len(newV) > 0 {
		s.Audit.Record(ctx, actorID, audit.EventRoleUpdated, map[string]any{"role_id": r.ID, "name": r.Name, "old": oldV, "new": newV})
	}
	return s.view(ctx, r)
}

// syncHolders refreshes users.role for everyone a permission change on r affects.
func (s *RolesService) syncHolders(ctx context.Context, r *role.Role) error {
	if r.Is(role.BuiltinMember) {
		return s.Roles.SyncLegacyRole(ctx, nil)
	}
	holders, err := s.Roles.UserIDsWithRole(ctx, r.ID)
	if err != nil {
		return err
	}
	return s.Roles.SyncLegacyRole(ctx, holders)
}

func (s *RolesService) Delete(ctx context.Context, actorID, id string) error {
	var r *role.Role
	var holders []string
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.Roles.Lock(ctx); err != nil {
			return err
		}
		var err error
		if r, err = s.find(ctx, id); err != nil {
			return err
		}
		a, err := s.actor(ctx, actorID)
		if err != nil {
			return err
		}
		if r.IsBuiltin() {
			return ErrBuiltin
		}
		if !a.CanManageRole(r) {
			return ErrHierarchy
		}
		if holders, err = s.Roles.UserIDsWithRole(ctx, r.ID); err != nil {
			return err
		}
		if err := s.Roles.Delete(ctx, r.ID); err != nil {
			return notFound(err)
		}
		return s.Roles.SyncLegacyRole(ctx, holders)
	})
	if err != nil {
		return err
	}
	s.Audit.Record(ctx, actorID, audit.EventRoleDeleted, map[string]any{"role_id": r.ID, "role": snapshot(r), "member_count": len(holders)})
	return nil
}

// reorderPositions gives n roles (most senior first) strictly decreasing
// positions taken from their current ones, nudging duplicates apart and
// keeping everything within MinPosition..MaxPosition.
func reorderPositions(current []int) []int {
	ps := slices.Clone(current)
	slices.SortFunc(ps, func(a, b int) int { return b - a })
	for i := 1; i < len(ps); i++ {
		if ps[i] >= ps[i-1] {
			ps[i] = ps[i-1] - 1
		}
	}
	if n := len(ps); n > 0 && ps[n-1] < MinPosition {
		shift := MinPosition - ps[n-1]
		for i := range ps {
			ps[i] += shift
		}
	}
	for i := range ps {
		ps[i] = min(ps[i], MaxPosition-i)
	}
	return ps
}

func (s *RolesService) Reorder(ctx context.Context, actorID string, order []string) ([]*View, error) {
	if len(order) == 0 {
		return nil, apperr.Invalid("order must list at least one role id")
	}
	if len(order) > MaxPosition {
		return nil, apperr.Invalid("too many roles")
	}
	seen := map[string]bool{}
	for _, id := range order {
		if !validID(id) || seen[id] {
			return nil, apperr.Invalid("order must list distinct role ids")
		}
		seen[id] = true
	}
	type change struct {
		r        *role.Role
		from, to int
	}
	var changes []change
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.Roles.Lock(ctx); err != nil {
			return err
		}
		a, err := s.actor(ctx, actorID)
		if err != nil {
			return err
		}
		all, err := s.Roles.List(ctx)
		if err != nil {
			return err
		}
		byID := map[string]*role.Role{}
		for _, r := range all {
			byID[r.ID] = r
		}
		listed := make([]*role.Role, 0, len(order))
		current := make([]int, 0, len(order))
		for _, id := range order {
			r, ok := byID[id]
			if !ok {
				return apperr.Invalid("unknown role " + id)
			}
			if r.Is(role.BuiltinOwner) || r.Is(role.BuiltinMember) {
				return apperr.Invalid("the Owner and Member positions are fixed")
			}
			listed = append(listed, r)
			current = append(current, r.Position)
		}
		now := s.now()
		for i, to := range reorderPositions(current) {
			r := listed[i]
			if r.Position == to {
				continue
			}
			if !a.CanManageRole(r) || !a.CanPlaceAt(to) {
				return ErrHierarchy
			}
			changes = append(changes, change{r: r, from: r.Position, to: to})
			r.Position, r.UpdatedAt = to, now
			if err := s.Roles.Save(ctx, r); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, c := range changes {
		s.Audit.Record(ctx, actorID, audit.EventRoleUpdated, map[string]any{
			"role_id": c.r.ID, "name": c.r.Name, "reorder": true,
			"old": map[string]any{"position": c.from}, "new": map[string]any{"position": c.to},
		})
	}
	return s.List(ctx)
}

func encodeCursor(userID string) string { return base64.RawURLEncoding.EncodeToString([]byte(userID)) }

func decodeCursor(c string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil || !ids.HasPrefix(string(b), ids.User) {
		return "", errCursor
	}
	return string(b), nil
}

func (s *RolesService) Members(ctx context.Context, id, cursor string, limit int) ([]*Member, string, error) {
	r, err := s.find(ctx, id)
	if err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 50
	}
	limit = min(limit, MaxPageSize)
	after := ""
	if cursor != "" {
		if after, err = decodeCursor(cursor); err != nil {
			return nil, "", err
		}
	}
	list, err := s.Roles.Members(ctx, r.ID, r.Is(role.BuiltinMember), after, limit+1)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(list) > limit {
		list = list[:limit]
		next = encodeCursor(list[limit-1].ID)
	}
	return list, next, nil
}

func (s *RolesService) AssignedForUsers(ctx context.Context, userIDs []string) (map[string][]*role.Role, error) {
	byUser, err := s.Roles.RoleIDsForUsers(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]*role.Role, len(userIDs))
	if len(byUser) == 0 {
		return out, nil
	}
	all, err := s.Roles.List(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[string]*role.Role{}
	for _, r := range all {
		byID[r.ID] = r
	}
	for uid, rids := range byUser {
		for _, rid := range rids {
			if r, ok := byID[rid]; ok {
				out[uid] = append(out[uid], r)
			}
		}
	}
	return out, nil
}

func (s *RolesService) SetUserRoles(ctx context.Context, actorID, userID string, roleIDs []string) ([]*role.Role, error) {
	if len(roleIDs) > maxAssign {
		return nil, apperr.Invalid("too many roles")
	}
	if !textutil.Storable(userID) {
		return nil, apperr.ErrNotFound
	}
	var result []*role.Role
	var oldIDs, newIDs, added, removed []string
	err := s.Tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.Roles.Lock(ctx); err != nil {
			return err
		}
		if _, err := s.Users.FindByID(ctx, userID); err != nil {
			return notFound(err)
		}
		a, err := s.actor(ctx, actorID)
		if err != nil {
			return err
		}
		all, err := s.Roles.List(ctx)
		if err != nil {
			return err
		}
		byID := map[string]*role.Role{}
		for _, r := range all {
			byID[r.ID] = r
		}
		want := map[string]bool{}
		for _, id := range roleIDs {
			r, ok := byID[id]
			if !ok || !validID(id) {
				return apperr.Invalid("unknown role " + id)
			}
			if !r.Is(role.BuiltinMember) {
				want[id] = true
			}
		}
		cur, err := s.Roles.ForUser(ctx, userID)
		if err != nil {
			return err
		}
		target := NewAccess(userID, cur)
		have := map[string]bool{}
		for _, r := range target.Assigned() {
			have[r.ID] = true
			oldIDs = append(oldIDs, r.ID)
		}
		var changed []*role.Role
		for _, r := range all { // most senior first
			switch {
			case want[r.ID] && !have[r.ID]:
				added = append(added, r.ID)
				changed = append(changed, r)
			case have[r.ID] && !want[r.ID]:
				removed = append(removed, r.ID)
				changed = append(changed, r)
			}
			if want[r.ID] {
				newIDs = append(newIDs, r.ID)
				result = append(result, r)
			}
		}
		if len(changed) == 0 {
			return nil
		}
		if actorID != userID && !a.Outranks(target) {
			return ErrHierarchy
		}
		for _, r := range changed {
			if !a.CanManageRole(r) {
				return ErrHierarchy
			}
		}
		if slices.Contains(removed, role.OwnerID) {
			n, err := s.Roles.CountHolders(ctx, role.OwnerID)
			if err != nil {
				return err
			}
			if n <= 1 {
				return ErrLastOwner
			}
		}
		var by *string
		if actorID != "" {
			by = &actorID
		}
		if err := s.Roles.RemoveUserRoles(ctx, userID, removed); err != nil {
			return err
		}
		if err := s.Roles.AddUserRoles(ctx, userID, added, by, s.Now().UTC()); err != nil {
			return err
		}
		return s.Roles.SyncLegacyRole(ctx, []string{userID})
	})
	if err != nil {
		return nil, err
	}
	if len(added)+len(removed) > 0 {
		s.Audit.RecordTarget(ctx, actorID, userID, audit.EventUserRolesChanged, map[string]any{
			"user_id": userID, "old": nonNil(oldIDs), "new": nonNil(newIDs), "added": nonNil(added), "removed": nonNil(removed),
		})
	}
	if result == nil {
		result = []*role.Role{}
	}
	return result, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *RolesService) SetLegacyRole(ctx context.Context, actorID, userID, legacy string) error {
	if legacy != user.RoleUser && legacy != user.RoleAdmin && legacy != role.BuiltinOwner {
		return apperr.Invalid("role must be user, admin or owner")
	}
	if !textutil.Storable(userID) {
		return apperr.ErrNotFound
	}
	if _, err := s.Users.FindByID(ctx, userID); err != nil {
		return notFound(err)
	}
	cur, err := s.Access(ctx, userID)
	if err != nil {
		return err
	}
	var want []string
	for _, r := range cur.Assigned() {
		if legacy == user.RoleUser && slices.Contains(EffectivePermissions(r), perm.AdminPanel) {
			continue
		}
		want = append(want, r.ID)
	}
	switch {
	case legacy == role.BuiltinOwner:
		want = append(want, role.OwnerID)
	case legacy == user.RoleAdmin && !cur.Has(perm.AdminPanel):
		want = append(want, role.AdminID)
	}
	_, err = s.SetUserRoles(ctx, actorID, userID, want)
	return err
}

func (s *RolesService) CheckAssign(ctx context.Context, actorID, roleID string) error {
	a, err := s.actor(ctx, actorID)
	if err != nil {
		return err
	}
	r, err := s.find(ctx, roleID)
	if err != nil {
		return err
	}
	if !a.CanManageRole(r) {
		return ErrHierarchy
	}
	return nil
}

func (s *RolesService) CheckManageUser(ctx context.Context, actorID, targetID string) error {
	if actorID == "" || actorID == targetID {
		return nil
	}
	a, err := s.Access(ctx, actorID)
	if err != nil {
		return err
	}
	t, err := s.Access(ctx, targetID)
	if err != nil {
		return err
	}
	if !a.Outranks(t) {
		return ErrHierarchy
	}
	return nil
}

func (s *RolesService) Version(ctx context.Context) ([]*role.Role, string, error) {
	rs, err := s.Roles.List(ctx)
	if err != nil {
		return nil, "", err
	}
	b, err := json.Marshal(rs)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(b)
	return rs, hex.EncodeToString(sum[:12]), nil
}

func (s *RolesService) PublicUserRoles(ctx context.Context, usernames []string) (map[string][]string, error) {
	if len(usernames) == 0 {
		return nil, apperr.Invalid("give at least one username")
	}
	if len(usernames) > MaxLookupUsernames {
		return nil, apperr.Invalid(fmt.Sprintf("at most %d usernames", MaxLookupUsernames))
	}
	byFold := map[string][]string{} // folded → requested spellings
	var folded []string
	for _, u := range usernames {
		u = strings.TrimSpace(u)
		if u == "" || len(u) > nick.MaxLen || !textutil.Storable(u) {
			continue
		}
		f := nick.Fold(u)
		if _, ok := byFold[f]; !ok {
			folded = append(folded, f)
		}
		byFold[f] = append(byFold[f], u)
	}
	out := map[string][]string{}
	if len(folded) == 0 {
		return out, nil
	}
	rows, err := s.Roles.RolesByUsernames(ctx, folded)
	if err != nil {
		return nil, err
	}
	all, err := s.Roles.List(ctx)
	if err != nil {
		return nil, err
	}
	visible := map[string]bool{}
	for _, r := range all {
		visible[r.ID] = Visible(r)
	}
	for _, row := range rows {
		rids := []string{}
		for _, id := range row.RoleIDs {
			if visible[id] {
				rids = append(rids, id)
			}
		}
		for _, asked := range byFold[row.UsernameFolded] {
			out[asked] = rids
		}
	}
	return out, nil
}

func (s *RolesService) IRC(ctx context.Context, u *user.User) (IRCInfo, *Access, error) {
	a, err := s.Access(ctx, u.ID)
	if err != nil {
		return IRCInfo{}, nil, err
	}
	return ComputeIRC(u.Username, a.Roles), a, nil
}

func (s *RolesService) IRCByUsername(ctx context.Context, username string) (*user.User, IRCInfo, *Access, error) {
	if username == "" || len(username) > nick.MaxLen || !textutil.Storable(username) {
		return nil, IRCInfo{}, nil, apperr.ErrNotFound
	}
	u, err := s.Users.FindByUsernameFolded(ctx, nick.Fold(username))
	if err != nil {
		return nil, IRCInfo{}, nil, notFound(err)
	}
	info, a, err := s.IRC(ctx, u)
	return u, info, a, err
}

func (s *RolesService) GrantsVersion(ctx context.Context) (string, error) {
	v, err := s.Roles.GrantsVersion(ctx)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(v, 10), nil
}

func (s *RolesService) Grants(ctx context.Context) (string, []Grant, error) {
	// The version is read first: the data that follows is at least as new,
	// so a poller never caches old data under a new version.
	version, err := s.GrantsVersion(ctx)
	if err != nil {
		return "", nil, err
	}
	all, err := s.Roles.List(ctx)
	if err != nil {
		return "", nil, err
	}
	byID := map[string]*role.Role{}
	var member *role.Role
	anyOf := []string{}
	for _, r := range all {
		byID[r.ID] = r
		if r.Is(role.BuiltinMember) {
			member = r
		}
		if EffectiveOper(r) || r.IRCVhost != nil {
			anyOf = append(anyOf, r.ID)
		}
	}
	if member != nil && slices.Contains(anyOf, member.ID) {
		anyOf = nil // Member supplies a grant: every enabled account qualifies
	}
	rows, err := s.Roles.EnabledUsersWithRoles(ctx, anyOf)
	if err != nil {
		return "", nil, err
	}
	out := []Grant{}
	for _, row := range rows {
		rs := make([]*role.Role, 0, len(row.RoleIDs)+1)
		for _, id := range row.RoleIDs {
			if r, ok := byID[id]; ok {
				rs = append(rs, r)
			}
		}
		if member != nil {
			rs = append(rs, member)
		}
		slices.SortStableFunc(rs, func(a, b *role.Role) int { return b.Position - a.Position })
		info := ComputeIRC(row.Username, rs)
		if info.OperClass != nil || info.Vhost != nil {
			out = append(out, Grant{Username: row.Username, IRCInfo: info})
		}
	}
	return version, out, nil
}
