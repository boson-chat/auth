package handlers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	nethttp "net/http"
	"regexp"
	"strings"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/perm"
	"github.com/boson-chat/auth/internal/reqmeta"
	"github.com/boson-chat/auth/internal/services/authn"
	"github.com/boson-chat/auth/internal/textutil"
)

const (
	// ActingAccountHeader names the account RoleServ acts for (the Ergo
	// account = auth username, matched with RFC 1459 folding).
	ActingAccountHeader = "X-Acting-Account"
	// ActingViaHeader names the acting service for the audit log (meta.via).
	ActingViaHeader = "X-Acting-Via"
	// defaultVia is meta.via when the caller doesn't send X-Acting-Via.
	defaultVia = "roleserv"
)

var viaRe = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// registerActing mounts the admin roles API mirrored under
// /internal/v1/acting for RoleServ: the same bodies, errors, permission and
// hierarchy checks and audit events, with the acting user named in
// X-Acting-Account instead of authenticated by an access token. Only with
// INTERNAL_ACTING_TOKEN set; otherwise the whole prefix is 404.
func (h *Handlers) registerActing(mux *nethttp.ServeMux) {
	if h.Config.InternalConfig.ActingToken == "" {
		return
	}
	acting := h.acting()
	manage := func(next nethttp.HandlerFunc) nethttp.HandlerFunc { return acting(perm.RolesManage)(next) }
	mux.HandleFunc("GET /internal/v1/acting/me", acting()(h.actingMe))
	mux.HandleFunc("POST /internal/v1/acting/roles", manage(h.adminCreateRole))
	mux.HandleFunc("PATCH /internal/v1/acting/roles/{id}", manage(h.adminUpdateRole))
	mux.HandleFunc("DELETE /internal/v1/acting/roles/{id}", manage(h.adminDeleteRole))
	mux.HandleFunc("PUT /internal/v1/acting/users/{id}/roles", manage(h.adminSetUserRoles))
}

// acting authenticates the caller by INTERNAL_ACTING_TOKEN (never
// INTERNAL_API_TOKEN), loads the acting account like a session user
// (unknown or disabled → 403 forbidden) and, like allow, requires one of
// perms read from the database. Downstream handlers see the account as
// the principal, so the admin handlers serve these routes unchanged.
func (h *Handlers) acting() func(perms ...string) func(nethttp.HandlerFunc) nethttp.HandlerFunc {
	wantSum := sha256.Sum256([]byte(h.Config.InternalConfig.ActingToken))
	return func(perms ...string) func(nethttp.HandlerFunc) nethttp.HandlerFunc {
		return func(next nethttp.HandlerFunc) nethttp.HandlerFunc {
			return func(w nethttp.ResponseWriter, r *nethttp.Request) {
				got := sha256.Sum256([]byte(r.Header.Get(InternalTokenHeader)))
				if subtle.ConstantTimeCompare(got[:], wantSum[:]) != 1 {
					writeError(w, r, apperr.ErrUnauthenticated)
					return
				}
				name := strings.TrimSpace(r.Header.Get(ActingAccountHeader))
				if name == "" || len(name) > nick.MaxLen || !textutil.Storable(name) {
					writeError(w, r, apperr.ErrForbidden)
					return
				}
				u, _, a, err := h.Roles.IRCByUsername(r.Context(), name)
				if err != nil {
					if e, ok := apperr.As(err); ok && e.Status == nethttp.StatusNotFound {
						err = apperr.ErrForbidden
					}
					writeError(w, r, err)
					return
				}
				if u.Disabled() || (len(perms) > 0 && !a.HasAny(perms...)) {
					writeError(w, r, apperr.ErrForbidden)
					return
				}
				if id := r.PathValue("id"); id != "" && !textutil.Storable(id) {
					writeError(w, r, apperr.ErrNotFound)
					return
				}
				via := strings.ToLower(strings.TrimSpace(r.Header.Get(ActingViaHeader)))
				if !viaRe.MatchString(via) {
					via = defaultVia
				}
				m := reqmeta.From(r.Context())
				if ip, ok := ForwardedClientIP(r); ok {
					m.IP = ip
				}
				m.Via = via
				ctx := reqmeta.With(r.Context(), m)
				ctx = context.WithValue(ctx, principalKey{}, &authn.Principal{UserID: u.ID, User: u})
				ctx = context.WithValue(ctx, accessKey{}, a)
				next(w, r.WithContext(ctx))
			}
		}
	}
}

// actingMe: GET /internal/v1/acting/me → {username, permissions} (effective).
func (h *Handlers) actingMe(w nethttp.ResponseWriter, r *nethttp.Request) {
	p, a := principalFrom(r), accessFrom(r)
	writeJSON(w, nethttp.StatusOK, map[string]any{"username": p.User.Username, "permissions": a.Permissions})
}
