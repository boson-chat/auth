package handlers

import (
	nethttp "net/http"
	"strings"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	fedrepo "github.com/boson-chat/auth/internal/db/repositories/federation"
	"github.com/boson-chat/auth/internal/perm"
	"github.com/boson-chat/auth/internal/services/federation"
)

// FederationPaths get CORS * without credentials: apps on any origin call
// a home's assertion endpoint and a remote's login endpoint with bearer
// tokens / assertions in the request, never cookies.
func FederationPaths(path string) bool {
	return path == federationMetadataPath || path == "/v1/federation/assertions" || path == "/v1/federation/login" ||
		path == "/v1/users/identities" || (strings.HasPrefix(path, "/v1/users/") && strings.HasSuffix(path, "/identity"))
}

const federationMetadataPath = "/.well-known/boson-federation.json"

func (h *Handlers) registerFederation(mux *nethttp.ServeMux) {
	if h.Federation == nil {
		return
	}
	mux.HandleFunc("GET "+federationMetadataPath, h.federationMetadata)
	mux.HandleFunc("POST /v1/federation/assertions", h.authed(h.federationAssert))
	mux.HandleFunc("POST /v1/federation/login", h.federationLogin)
	mux.HandleFunc("GET /v1/users/{handle}/identity", h.userIdentity)
	mux.HandleFunc("POST /v1/users/identities", h.userIdentities)

	// The admin panel's Federation page (settings.manage) lists remote
	// users too, so users.view or settings.manage may read them.
	view := h.allow(perm.UsersView, perm.SettingsManage)
	moderate := h.allow(perm.UsersModerate, perm.UsersManage)
	settingsView, settingsManage := h.allow(perm.AdminPanel, perm.SettingsManage), h.allow(perm.SettingsManage)
	mux.HandleFunc("GET /v1/admin/federation", settingsView(h.adminFederationSettings))
	mux.HandleFunc("PATCH /v1/admin/federation", settingsManage(h.adminFederationUpdateSettings))
	mux.HandleFunc("GET /v1/admin/federation/users", view(h.adminFederationUsers))
	mux.HandleFunc("GET /v1/admin/federation/users/{id}", view(h.adminFederationUser))
	mux.HandleFunc("POST /v1/admin/federation/users/{id}/ban", moderate(h.adminFederationBan))
	mux.HandleFunc("DELETE /v1/admin/federation/users/{id}/ban", moderate(h.adminFederationUnban))
	mux.HandleFunc("GET /v1/admin/federation/bans", view(h.adminFederationBans))
	mux.HandleFunc("POST /v1/admin/federation/domains/{domain}/revoke-sessions",
		h.allow(perm.SettingsManage, perm.UsersModerate, perm.UsersManage)(h.adminFederationRevokeDomain))
}

// userIdentity: GET /v1/users/{handle}/identity, public and rate-limited
// per IP (BucketPublic): whether a local handle is a federated account and
// whose. Unknown handles answer like local ones.
func (h *Handlers) userIdentity(w nethttp.ResponseWriter, r *nethttp.Request) {
	if !h.Limits.allow(w, r, BucketPublic, "") {
		return
	}
	handle := r.PathValue("handle")
	m, err := h.Federation.Identities(r.Context(), []string{handle})
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, nethttp.StatusOK, m[handle])
}

type identitiesReq struct {
	Handles []string `json:"handles"`
}

// userIdentities: POST /v1/users/identities {handles} → {identities: {handle: Identity}}.
func (h *Handlers) userIdentities(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req identitiesReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if !h.Limits.allow(w, r, BucketPublic, "") {
		return
	}
	m, err := h.Federation.Identities(r.Context(), req.Handles)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"identities": m})
}

func (h *Handlers) federationMetadata(w nethttp.ResponseWriter, r *nethttp.Request) {
	md, err := h.Federation.Metadata(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, nethttp.StatusOK, md)
}

type assertReq struct {
	Audience string `json:"audience"`
}

func (h *Handlers) federationAssert(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req assertReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	p := principalFrom(r)
	if !h.Limits.allow(w, r, BucketFederationAssert, "id:"+p.UserID) {
		return
	}
	tok, exp, err := h.Federation.Assert(r.Context(), p, req.Audience)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, nethttp.StatusOK, map[string]any{"assertion": tok, "expires_in": int64(time.Until(exp).Seconds())})
}

type federationLoginReq struct {
	Assertion string `json:"assertion"`
	// Cookie: tokens as HttpOnly cookies (same-origin web apps only).
	Cookie bool `json:"cookie"`
}

type federationLoginResponse struct {
	tokenResponse
	Federated bool   `json:"federated"`
	Identity  string `json:"identity"`
	Handle    string `json:"handle"`
}

func (h *Handlers) federationLogin(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req federationLoginReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if req.Cookie {
		if err := requireCSRFHeader(r); err != nil {
			writeError(w, r, err)
			return
		}
	}
	if !h.Limits.allow(w, r, BucketFederationLogin, "") {
		return
	}
	res, err := h.Federation.Login(r.Context(), req.Assertion)
	if err != nil {
		writeError(w, r, err)
		return
	}
	resp := federationLoginResponse{tokenResponse: h.tokenBody(w, res.Tokens, req.Cookie),
		Federated: true, Identity: res.Identity, Handle: res.Tokens.User.Username}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, nethttp.StatusOK, resp)
}

// federationJSON describes a user's federated identity (GET /v1/me).
type federationJSON struct {
	Identity   string `json:"identity"`
	HomeDomain string `json:"home_domain"`
	Issuer     string `json:"issuer"`
}

func toFederation(a *fedrepo.Account) *federationJSON {
	if a == nil {
		return nil
	}
	return &federationJSON{Identity: a.Identity(), HomeDomain: a.HomeDomain, Issuer: a.Issuer}
}

type remoteUserJSON struct {
	ID            string     `json:"id"`
	Identity      string     `json:"identity"`
	Handle        string     `json:"handle"`
	HomeDomain    string     `json:"home_domain"`
	HomeUsername  string     `json:"home_username"`
	Issuer        string     `json:"issuer"`
	Subject       string     `json:"subject"`
	DisplayName   string     `json:"display_name"`
	Picture       *string    `json:"picture"`
	EmailVerified bool       `json:"email_verified"`
	FirstSeenAt   time.Time  `json:"first_seen_at"`
	LastLoginAt   time.Time  `json:"last_login_at"`
	LastSeenAt    *time.Time `json:"last_seen_at"`
	Banned        bool       `json:"banned"`
	BannedAt      *time.Time `json:"banned_at,omitempty"`
	BanReason     string     `json:"ban_reason,omitempty"`
	DomainBlocked bool       `json:"domain_blocked"`
	Disabled      bool       `json:"disabled"`
	Sessions      int        `json:"sessions"`
}

func toRemoteUser(v *fedrepo.AccountView, block []string) remoteUserJSON {
	seen := v.LastActiveAt
	if seen == nil || v.LastLoginAt.After(*seen) {
		t := v.LastLoginAt
		seen = &t
	}
	reason := ""
	if v.BanReason != nil {
		reason = *v.BanReason
	}
	return remoteUserJSON{
		ID: v.UserID, Identity: v.Identity(), Handle: v.Username, HomeDomain: v.HomeDomain, HomeUsername: v.HomeUsername,
		Issuer: v.Issuer, Subject: v.Subject, DisplayName: v.DisplayName, Picture: v.Picture, EmailVerified: v.EmailVerified,
		FirstSeenAt: v.CreatedAt, LastLoginAt: v.LastLoginAt, LastSeenAt: seen,
		Banned: v.Banned, BannedAt: v.BannedAt, BanReason: reason,
		DomainBlocked: config.DomainListMatches(block, v.HomeDomain), Disabled: v.DisabledAt != nil, Sessions: v.Sessions,
	}
}

// blockList is the effective block list (for domain_blocked).
func (h *Handlers) blockList(r *nethttp.Request) ([]string, error) {
	st, err := h.Federation.Settings(r.Context())
	return st.Block, err
}

func (h *Handlers) adminFederationUsers(w nethttp.ResponseWriter, r *nethttp.Request) {
	q := r.URL.Query()
	list, total, next, err := h.Federation.ListUsers(r.Context(), fedrepo.ListFilter{
		Query: q.Get("q"), Domain: q.Get("domain"), Limit: intParam(r, "limit"),
	}, q.Get("cursor"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	block, err := h.blockList(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := make([]remoteUserJSON, 0, len(list))
	for _, v := range list {
		out = append(out, toRemoteUser(v, block))
	}
	var nextCursor *string
	if next != "" {
		nextCursor = &next
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"users": out, "next_cursor": nextCursor, "total": total})
}

// remoteUser answers with one remote user (a bare RemoteUser object).
func (h *Handlers) remoteUser(w nethttp.ResponseWriter, r *nethttp.Request, v *fedrepo.AccountView, err error) {
	if err != nil {
		writeError(w, r, err)
		return
	}
	block, err := h.blockList(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, toRemoteUser(v, block))
}

func (h *Handlers) adminFederationUser(w nethttp.ResponseWriter, r *nethttp.Request) {
	v, err := h.Federation.GetUser(r.Context(), r.PathValue("id"))
	h.remoteUser(w, r, v, err)
}

type banReq struct {
	Reason string `json:"reason"`
}

func (h *Handlers) adminFederationBan(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req banReq
	if err := decodeOptional(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	v, err := h.Federation.Ban(r.Context(), principalFrom(r).UserID, r.PathValue("id"), req.Reason)
	h.remoteUser(w, r, v, err)
}

func (h *Handlers) adminFederationUnban(w nethttp.ResponseWriter, r *nethttp.Request) {
	v, err := h.Federation.Unban(r.Context(), principalFrom(r).UserID, r.PathValue("id"))
	h.remoteUser(w, r, v, err)
}

func (h *Handlers) adminFederationBans(w nethttp.ResponseWriter, r *nethttp.Request) {
	list, err := h.Federation.ListBans(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	type banJSON struct {
		Identity  string    `json:"identity"`
		Issuer    string    `json:"issuer"`
		Subject   string    `json:"subject"`
		Reason    string    `json:"reason"`
		CreatedBy *string   `json:"created_by"`
		CreatedAt time.Time `json:"created_at"`
	}
	out := make([]banJSON, 0, len(list))
	for _, b := range list {
		out = append(out, banJSON{b.Identity, b.Issuer, b.Subject, b.Reason, b.CreatedBy, b.CreatedAt})
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"bans": out})
}

func (h *Handlers) adminFederationRevokeDomain(w nethttp.ResponseWriter, r *nethttp.Request) {
	d := strings.TrimSpace(r.PathValue("domain"))
	if d == "" {
		writeError(w, r, apperr.ErrNotFound)
		return
	}
	domain, n, err := h.Federation.RevokeDomainSessions(r.Context(), principalFrom(r).UserID, d)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"domain": domain, "revoked": n})
}

func (h *Handlers) adminFederationSettings(w nethttp.ResponseWriter, r *nethttp.Request) {
	st, err := h.Federation.AdminSettings(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, st)
}

func (h *Handlers) adminFederationUpdateSettings(w nethttp.ResponseWriter, r *nethttp.Request) {
	var p federation.Patch
	if err := decode(w, r, &p); err != nil {
		writeError(w, r, err)
		return
	}
	st, err := h.Federation.UpdateSettings(r.Context(), principalFrom(r).UserID, p)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, st)
}
