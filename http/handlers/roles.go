package handlers

import (
	nethttp "net/http"
	"strings"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories/role"
	"github.com/boson-chat/auth/internal/perm"
	"github.com/boson-chat/auth/internal/services/roles"
)

// publicRolesMaxAge is the Cache-Control max-age of the public role endpoints.
const publicRolesMaxAge = "public, max-age=60"

func (h *Handlers) registerRoles(mux *nethttp.ServeMux) {
	panel, manage := h.allow(perm.AdminPanel), h.allow(perm.RolesManage)
	mux.HandleFunc("GET /v1/admin/permissions", panel(h.adminListPermissions))
	mux.HandleFunc("GET /v1/admin/roles", panel(h.adminListRoles))
	mux.HandleFunc("POST /v1/admin/roles", manage(h.adminCreateRole))
	mux.HandleFunc("POST /v1/admin/roles/reorder", manage(h.adminReorderRoles))
	mux.HandleFunc("GET /v1/admin/roles/{id}", panel(h.adminGetRole))
	mux.HandleFunc("PATCH /v1/admin/roles/{id}", manage(h.adminUpdateRole))
	mux.HandleFunc("DELETE /v1/admin/roles/{id}", manage(h.adminDeleteRole))
	mux.HandleFunc("GET /v1/admin/roles/{id}/members", panel(h.adminRoleMembers))
	mux.HandleFunc("PUT /v1/admin/users/{id}/roles", manage(h.adminSetUserRoles))

	mux.HandleFunc("GET /v1/roles", h.publicRoles)
	mux.HandleFunc("GET /v1/users/roles", h.publicUserRoles)
}

type roleIRCJSON struct {
	WhoisLine *string `json:"whois_line"`
	Vhost     *string `json:"vhost"`
	Oper      bool    `json:"oper"`
}

type roleJSON struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Slug        string      `json:"slug"`
	Color       *string     `json:"color"`
	Position    int         `json:"position"`
	Builtin     *string     `json:"builtin"`
	Permissions []string    `json:"permissions"`
	IRC         roleIRCJSON `json:"irc"`
	Hoist       bool        `json:"hoist"`
	Mentionable bool        `json:"mentionable"`
	MemberCount int64       `json:"member_count"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

func toRole(v *roles.View) roleJSON {
	r := v.Role
	return roleJSON{
		ID: r.ID, Name: r.Name, Slug: r.Slug, Color: r.Color, Position: r.Position, Builtin: r.Builtin,
		Permissions: roles.EffectivePermissions(r),
		IRC:         roleIRCJSON{WhoisLine: r.IRCWhoisLine, Vhost: r.IRCVhost, Oper: roles.EffectiveOper(r)},
		Hoist:       r.Hoist, Mentionable: r.Mentionable, MemberCount: v.MemberCount,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func toRoles(vs []*roles.View) []roleJSON {
	out := make([]roleJSON, 0, len(vs))
	for _, v := range vs {
		out = append(out, toRole(v))
	}
	return out
}

// roleSummaryJSON is a role as listed on a user.
type roleSummaryJSON struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Color    *string `json:"color"`
	Position int     `json:"position"`
}

func toRoleSummaries(rs []*role.Role) []roleSummaryJSON {
	out := make([]roleSummaryJSON, 0, len(rs))
	for _, r := range rs {
		out = append(out, roleSummaryJSON{ID: r.ID, Name: r.Name, Color: r.Color, Position: r.Position})
	}
	return out
}

// adminUserJSON is a user in admin listings, with their assigned roles.
type adminUserJSON struct {
	adminUserBaseJSON
	Roles []roleSummaryJSON `json:"roles"`
}

func (h *Handlers) adminListPermissions(w nethttp.ResponseWriter, _ *nethttp.Request) {
	writeJSON(w, nethttp.StatusOK, map[string]any{"permissions": perm.All()})
}

func (h *Handlers) adminListRoles(w nethttp.ResponseWriter, r *nethttp.Request) {
	vs, err := h.Roles.List(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"roles": toRoles(vs)})
}

func (h *Handlers) adminGetRole(w nethttp.ResponseWriter, r *nethttp.Request) {
	vs, err := h.Roles.List(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	for _, v := range vs {
		if v.ID == r.PathValue("id") {
			writeJSON(w, nethttp.StatusOK, map[string]any{"role": toRole(v)})
			return
		}
	}
	writeError(w, r, apperr.ErrNotFound)
}

func (h *Handlers) adminCreateRole(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in roles.Input
	if err := decode(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	v, err := h.Roles.Create(r.Context(), principalFrom(r).UserID, in)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusCreated, map[string]any{"role": toRole(v)})
}

func (h *Handlers) adminUpdateRole(w nethttp.ResponseWriter, r *nethttp.Request) {
	var in roles.Input
	if err := decode(w, r, &in); err != nil {
		writeError(w, r, err)
		return
	}
	var err error
	if in.IfMatch, err = ifMatch(r); err != nil {
		writeError(w, r, err)
		return
	}
	v, err := h.Roles.Update(r.Context(), principalFrom(r).UserID, r.PathValue("id"), in)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"role": toRole(v)})
}

func (h *Handlers) adminDeleteRole(w nethttp.ResponseWriter, r *nethttp.Request) {
	if err := h.Roles.Delete(r.Context(), principalFrom(r).UserID, r.PathValue("id")); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(nethttp.StatusNoContent)
}

type reorderReq struct {
	Order []string `json:"order"`
}

func (h *Handlers) adminReorderRoles(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req reorderReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	vs, err := h.Roles.Reorder(r.Context(), principalFrom(r).UserID, req.Order)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"roles": toRoles(vs)})
}

type roleMemberJSON struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Disabled    bool       `json:"disabled"`
	AssignedAt  *time.Time `json:"assigned_at"`
	AssignedBy  *string    `json:"assigned_by"`
}

// adminRoleMembers: GET /v1/admin/roles/{id}/members?cursor=&limit=
func (h *Handlers) adminRoleMembers(w nethttp.ResponseWriter, r *nethttp.Request) {
	list, next, err := h.Roles.Members(r.Context(), r.PathValue("id"), r.URL.Query().Get("cursor"), intParam(r, "limit"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := make([]roleMemberJSON, 0, len(list))
	for _, m := range list {
		out = append(out, roleMemberJSON{ID: m.ID, Username: m.Username, DisplayName: m.DisplayName,
			Disabled: m.Disabled(), AssignedAt: m.AssignedAt, AssignedBy: m.AssignedBy})
	}
	var nextCursor *string
	if next != "" {
		nextCursor = &next
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"users": out, "next_cursor": nextCursor})
}

type setUserRolesReq struct {
	RoleIDs *[]string `json:"role_ids"`
}

func (h *Handlers) adminSetUserRoles(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req setUserRolesReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if req.RoleIDs == nil {
		writeError(w, r, apperr.Invalid("role_ids is required"))
		return
	}
	rs, err := h.Roles.SetUserRoles(r.Context(), principalFrom(r).UserID, r.PathValue("id"), *req.RoleIDs)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"roles": toRoleSummaries(rs)})
}

var errBadIfMatch = apperr.Invalid("If-Match must be the role's updated_at (RFC 3339)")

// ifMatch parses an optional If-Match: <updated_at> (quotes allowed).
func ifMatch(r *nethttp.Request) (*time.Time, error) {
	v := strings.TrimSpace(r.Header.Get("If-Match"))
	if v == "" || v == "*" {
		return nil, nil
	}
	v = strings.Trim(strings.TrimPrefix(v, "W/"), `"`)
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return nil, errBadIfMatch
	}
	return &t, nil
}

// notModified sets the ETag and reports (after writing 304) whether the
// client's If-None-Match already has it.
func notModified(w nethttp.ResponseWriter, r *nethttp.Request, version string) bool {
	etag := `"` + version + `"`
	w.Header().Set("ETag", etag)
	for _, tag := range strings.Split(r.Header.Get("If-None-Match"), ",") {
		tag = strings.TrimPrefix(strings.TrimSpace(tag), "W/")
		if tag == etag || tag == "*" {
			w.WriteHeader(nethttp.StatusNotModified)
			return true
		}
	}
	return false
}

type publicRoleJSON struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Color       *string `json:"color"`
	Position    int     `json:"position"`
	Hoist       bool    `json:"hoist"`
	Mentionable bool    `json:"mentionable"`
}

// publicRoles: GET /v1/roles, for clients' badges and colours.
func (h *Handlers) publicRoles(w nethttp.ResponseWriter, r *nethttp.Request) {
	if !h.Limits.allow(w, r, BucketPublic, "") {
		return
	}
	rs, version, err := h.Roles.Version(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", publicRolesMaxAge)
	if notModified(w, r, version) {
		return
	}
	out := make([]publicRoleJSON, 0, len(rs))
	for _, ro := range rs {
		out = append(out, publicRoleJSON{ID: ro.ID, Name: ro.Name, Color: ro.Color, Position: ro.Position, Hoist: ro.Hoist, Mentionable: ro.Mentionable})
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"roles": out})
}

// publicUserRoles: GET /v1/users/roles?username=a&username=b (or a,b), ≤ 100.
func (h *Handlers) publicUserRoles(w nethttp.ResponseWriter, r *nethttp.Request) {
	if !h.Limits.allow(w, r, BucketPublic, "") {
		return
	}
	var names []string
	for _, v := range r.URL.Query()["username"] {
		for n := range strings.SplitSeq(v, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
	}
	m, err := h.Roles.PublicUserRoles(r.Context(), names)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", publicRolesMaxAge)
	writeJSON(w, nethttp.StatusOK, map[string]any{"users": m})
}

type internalIRCJSON struct {
	WhoisLine    string   `json:"whois_line"`
	Vhost        *string  `json:"vhost"`
	Oper         bool     `json:"oper"`
	OperClass    *string  `json:"oper_class"`
	Capabilities []string `json:"capabilities"`
}

type internalRoleJSON struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Slug        string          `json:"slug"`
	Color       *string         `json:"color"`
	Position    int             `json:"position"`
	Builtin     *string         `json:"builtin"`
	Permissions []string        `json:"permissions"`
	IRC         internalIRCJSON `json:"irc"`
	Hoist       bool            `json:"hoist"`
	Mentionable bool            `json:"mentionable"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// internalRoles: GET /internal/v1/roles, from which Ergo renders oper classes.
func (h *Handlers) internalRoles(w nethttp.ResponseWriter, r *nethttp.Request) {
	rs, version, err := h.Roles.Version(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	if notModified(w, r, version) {
		return
	}
	out := make([]internalRoleJSON, 0, len(rs))
	for _, ro := range rs {
		irc := internalIRCJSON{WhoisLine: roles.EffectiveWhoisLine(ro), Vhost: ro.IRCVhost, Oper: roles.EffectiveOper(ro), Capabilities: roles.IRCCapabilities(ro)}
		if irc.Oper {
			slug := ro.Slug
			irc.OperClass = &slug
		}
		out = append(out, internalRoleJSON{
			ID: ro.ID, Name: ro.Name, Slug: ro.Slug, Color: ro.Color, Position: ro.Position, Builtin: ro.Builtin,
			Permissions: roles.EffectivePermissions(ro), IRC: irc, Hoist: ro.Hoist, Mentionable: ro.Mentionable, UpdatedAt: ro.UpdatedAt,
		})
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"version": version, "roles": out})
}

// internalUserIRC: GET /internal/v1/users/{username}/irc, for logins that
// don't go through verify-password (OAUTHBEARER / SSO).
func (h *Handlers) internalUserIRC(w nethttp.ResponseWriter, r *nethttp.Request) {
	u, irc, a, err := h.Roles.IRCByUsername(r.Context(), r.PathValue("username"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	// A federated account of a blocked home domain is reported disabled, so
	// the IRC auth-script refuses its OAUTHBEARER logins (the account itself
	// isn't disabled: unblocking lets it in again).
	disabled := u.Disabled()
	if !disabled && h.Federation != nil {
		if disabled, err = h.Federation.DomainBlocked(r.Context(), u.ID); err != nil {
			writeError(w, r, err)
			return
		}
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{
		"user_id": u.ID, "username": u.Username, "disabled": disabled,
		"irc": irc, "roles": a.RoleNames(roles.MaxTokenRoles), "permissions": a.Permissions,
	})
}

type ircGrantJSON struct {
	Username string `json:"username"`
	roles.IRCInfo
}

// internalIRCGrants: GET /internal/v1/irc/grants, every enabled account with
// an oper class or a vhost, so Ergo can apply admin-panel changes live.
func (h *Handlers) internalIRCGrants(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Header.Get("If-None-Match") != "" {
		version, err := h.Roles.GrantsVersion(r.Context())
		if err != nil {
			writeError(w, r, err)
			return
		}
		if notModified(w, r, version) {
			return
		}
	}
	version, gs, err := h.Roles.Grants(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+version+`"`)
	out := make([]ircGrantJSON, 0, len(gs))
	for _, g := range gs {
		out = append(out, ircGrantJSON{Username: g.Username, IRCInfo: g.IRCInfo})
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"version": version, "users": out})
}
