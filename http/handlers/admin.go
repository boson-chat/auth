package handlers

import (
	nethttp "net/http"
	"strconv"
	"strings"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories"
	auditrepo "github.com/boson-chat/auth/internal/db/repositories/audit"
	inviterepo "github.com/boson-chat/auth/internal/db/repositories/invite"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/services/admin"
	"github.com/boson-chat/auth/internal/services/settings"
)

func (h *Handlers) registerAdmin(mux *nethttp.ServeMux) {
	mux.HandleFunc("GET /v1/admin/users", h.adminOnly(h.adminListUsers))
	mux.HandleFunc("POST /v1/admin/users", h.adminOnly(h.adminCreateUser))
	mux.HandleFunc("POST /v1/admin/users/{id}/password-reset", h.adminOnly(h.adminSendPasswordReset))
	mux.HandleFunc("POST /v1/admin/users/{id}/verification", h.adminOnly(h.adminSendVerification))
	mux.HandleFunc("GET /v1/admin/users/{id}", h.adminOnly(h.adminGetUser))
	mux.HandleFunc("POST /v1/admin/users/{id}/disable", h.adminOnly(h.adminSetDisabled(true)))
	mux.HandleFunc("POST /v1/admin/users/{id}/enable", h.adminOnly(h.adminSetDisabled(false)))
	mux.HandleFunc("PATCH /v1/admin/users/{id}", h.adminOnly(h.adminUpdateUser))
	mux.HandleFunc("GET /v1/admin/users/{id}/sessions", h.adminOnly(h.adminListSessions))
	mux.HandleFunc("DELETE /v1/admin/sessions/{id}", h.adminOnly(h.adminRevokeSession))
	mux.HandleFunc("GET /v1/admin/invites", h.adminOnly(h.adminListInvites))
	mux.HandleFunc("POST /v1/admin/invites", h.adminOnly(h.adminCreateInvite))
	mux.HandleFunc("DELETE /v1/admin/invites/{id}", h.adminOnly(h.adminRevokeInvite))
	mux.HandleFunc("GET /v1/admin/audit", h.adminOnly(h.adminAudit))
	mux.HandleFunc("GET /v1/admin/settings", h.adminOnly(h.adminGetSettings))
	mux.HandleFunc("PATCH /v1/admin/settings", h.adminOnly(h.adminUpdateSettings))
}

func intParam(r *nethttp.Request, name string) int {
	n, _ := strconv.Atoi(r.URL.Query().Get(name))
	return n
}

func (h *Handlers) adminListUsers(w nethttp.ResponseWriter, r *nethttp.Request) {
	users, total, err := h.Admin.ListUsers(r.Context(), r.URL.Query().Get("q"), intParam(r, "limit"), intParam(r, "offset"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		out = append(out, toUser(u))
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"users": out, "total": total})
}

func (h *Handlers) adminGetUser(w nethttp.ResponseWriter, r *nethttp.Request) {
	u, err := h.Admin.GetUser(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	idents, err := h.SSO.ListIdentities(r.Context(), u.ID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	hasPW, err := h.SSO.HasPassword(r.Context(), u.ID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"user": toUser(u), "identities": toIdentities(idents), "has_password": hasPW})
}

func (h *Handlers) adminSetDisabled(disabled bool) nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		p := principalFrom(r)
		id := r.PathValue("id")
		if disabled && id == p.UserID {
			writeError(w, r, apperr.Invalid("you can't disable your own account"))
			return
		}
		u, err := h.Admin.SetDisabled(r.Context(), p.UserID, id, disabled)
		if err != nil {
			writeError(w, r, err)
			return
		}
		writeJSON(w, nethttp.StatusOK, map[string]any{"user": toUser(u)})
	}
}

type adminUpdateReq struct {
	Role *string `json:"role"`
}

func (h *Handlers) adminUpdateUser(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req adminUpdateReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	p := principalFrom(r)
	id := r.PathValue("id")
	if req.Role == nil {
		writeError(w, r, apperr.Invalid("nothing to update"))
		return
	}
	if id == p.UserID && *req.Role != "admin" {
		writeError(w, r, apperr.Invalid("you can't remove your own admin role"))
		return
	}
	u, err := h.Admin.SetRole(r.Context(), p.UserID, id, *req.Role)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"user": toUser(u)})
}

func (h *Handlers) adminListSessions(w nethttp.ResponseWriter, r *nethttp.Request) {
	list, err := h.Admin.ListSessions(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := make([]sessionJSON, 0, len(list))
	for _, s := range list {
		out = append(out, toSession(s, "", true))
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"sessions": out})
}

func (h *Handlers) adminRevokeSession(w nethttp.ResponseWriter, r *nethttp.Request) {
	if err := h.Admin.RevokeSession(r.Context(), principalFrom(r).UserID, r.PathValue("id")); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(nethttp.StatusNoContent)
}

type inviteJSON struct {
	ID        string     `json:"id"`
	Code      string     `json:"code,omitempty"` // only in the create response
	Note      string     `json:"note"`
	MaxUses   int        `json:"max_uses"`
	Uses      int        `json:"uses"`
	CreatedBy *string    `json:"created_by"`
	ExpiresAt *time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func toInvite(i *inviterepo.Invite, code string) inviteJSON {
	return inviteJSON{ID: i.ID, Code: code, Note: i.Note, MaxUses: i.MaxUses, Uses: i.Uses,
		CreatedBy: i.CreatedBy, ExpiresAt: i.ExpiresAt, RevokedAt: i.RevokedAt, CreatedAt: i.CreatedAt}
}

type createInviteReq struct {
	MaxUses int    `json:"max_uses"`
	TTL     string `json:"ttl"` // Go duration, e.g. "168h"; empty = never expires
	Note    string `json:"note"`
}

func (h *Handlers) adminCreateInvite(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req createInviteReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if req.MaxUses == 0 {
		req.MaxUses = 1
	}
	var ttl time.Duration
	if req.TTL != "" {
		var err error
		if ttl, err = time.ParseDuration(req.TTL); err != nil || ttl <= 0 {
			writeError(w, r, apperr.Invalid("ttl must be a positive duration like 168h"))
			return
		}
	}
	code, inv, err := h.Admin.CreateInvite(r.Context(), principalFrom(r).UserID, req.MaxUses, ttl, req.Note)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusCreated, map[string]any{"invite": toInvite(inv, code)})
}

func (h *Handlers) adminListInvites(w nethttp.ResponseWriter, r *nethttp.Request) {
	list, err := h.Admin.ListInvites(r.Context(), intParam(r, "limit"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := make([]inviteJSON, 0, len(list))
	for _, i := range list {
		out = append(out, toInvite(i, ""))
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"invites": out})
}

func (h *Handlers) adminRevokeInvite(w nethttp.ResponseWriter, r *nethttp.Request) {
	if err := h.Admin.RevokeInvite(r.Context(), principalFrom(r).UserID, r.PathValue("id")); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(nethttp.StatusNoContent)
}

type adminCreateUserReq struct {
	Username        string `json:"username"`
	Email           string `json:"email"`
	Role            string `json:"role"`
	Password        string `json:"password"`
	SendInviteEmail bool   `json:"send_invite_email"`
}

func (h *Handlers) adminCreateUser(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req adminCreateUserReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	u, sent, err := h.Admin.CreateUser(r.Context(), principalFrom(r).UserID, admin.CreateUserInput{
		Username: req.Username, Email: req.Email, Role: req.Role, Password: req.Password, SendSetupEmail: req.SendInviteEmail,
	})
	if err != nil && u == nil {
		writeError(w, r, err)
		return
	}
	if err != nil {
		// The account exists; only queuing the setup email failed. The admin
		// can retry with POST /v1/admin/users/{id}/password-reset.
		logger.FromCtx(r.Context()).Error().Err(err).Str("user_id", u.ID).Msg("account setup email")
	}
	writeJSON(w, nethttp.StatusCreated, map[string]any{"user": toUser(u), "invite_email_sent": sent})
}

func (h *Handlers) adminSendPasswordReset(w nethttp.ResponseWriter, r *nethttp.Request) {
	if err := h.Admin.SendPasswordReset(r.Context(), principalFrom(r).UserID, r.PathValue("id")); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusAccepted, map[string]string{"status": "a password reset link has been sent to the user's email address"})
}

func (h *Handlers) adminSendVerification(w nethttp.ResponseWriter, r *nethttp.Request) {
	if err := h.Admin.SendVerification(r.Context(), principalFrom(r).UserID, r.PathValue("id")); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusAccepted, map[string]string{"status": "a verification link has been sent to the user's email address"})
}

type auditEntryJSON struct {
	ID    string             `json:"id"`
	Event string             `json:"event"`
	At    time.Time          `json:"at"`
	IP    string             `json:"ip"`
	Meta  repositories.JSONB `json:"meta"`
	// UserID is the actor (kept for 1.2 clients); same as ActorUserID.
	UserID         *string `json:"user_id"`
	ActorUserID    *string `json:"actor_user_id"`
	ActorUsername  *string `json:"actor_username"`
	TargetUserID   *string `json:"target_user_id"`
	TargetUsername *string `json:"target_username"`
}

func toAuditEntry(e *auditrepo.EntryView) auditEntryJSON {
	meta := e.Meta
	if meta == nil {
		meta = repositories.JSONB{}
	}
	return auditEntryJSON{
		ID: e.ID, Event: e.Event, At: e.At, IP: e.IP, Meta: meta,
		UserID: e.UserID, ActorUserID: e.UserID, ActorUsername: e.ActorUsername,
		TargetUserID: e.TargetUserID, TargetUsername: e.TargetUsername,
	}
}

func timeParam(r *nethttp.Request, name string) (*time.Time, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return nil, apperr.Invalid(name + " must be an RFC 3339 timestamp")
	}
	return &t, nil
}

// adminAudit: GET /v1/admin/audit?event=&actor=&target=&user_id=&since=&until=&cursor=&limit=
func (h *Handlers) adminAudit(w nethttp.ResponseWriter, r *nethttp.Request) {
	q := r.URL.Query()
	since, err := timeParam(r, "since")
	if err != nil {
		writeError(w, r, err)
		return
	}
	until, err := timeParam(r, "until")
	if err != nil {
		writeError(w, r, err)
		return
	}
	var events []string
	if ev := q.Get("event"); ev != "" {
		events = strings.Split(ev, ",")
	}
	list, next, err := h.Admin.ListAudit(r.Context(), admin.AuditQuery{
		Events: events, Actor: q.Get("actor"), Target: q.Get("target"), UserID: q.Get("user_id"),
		Since: since, Until: until, Cursor: q.Get("cursor"), Limit: intParam(r, "limit"),
	})
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := make([]auditEntryJSON, 0, len(list))
	for _, e := range list {
		out = append(out, toAuditEntry(e))
	}
	var nextCursor *string
	if next != "" {
		nextCursor = &next
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"entries": out, "next_cursor": nextCursor})
}

func (h *Handlers) adminGetSettings(w nethttp.ResponseWriter, r *nethttp.Request) {
	st, err := h.Settings.Get(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, st)
}

func (h *Handlers) adminUpdateSettings(w nethttp.ResponseWriter, r *nethttp.Request) {
	var p settings.Patch
	if err := decode(w, r, &p); err != nil {
		writeError(w, r, err)
		return
	}
	st, err := h.Settings.Update(r.Context(), principalFrom(r).UserID, p)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, st)
}
