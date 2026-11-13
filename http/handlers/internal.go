package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	nethttp "net/http"
	"net/netip"
	"strings"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/reqmeta"
)

// InternalTokenHeader carries INTERNAL_API_TOKEN.
const InternalTokenHeader = "X-Internal-Token"

// RegisterInternal mounts the internal API (separate listener, never public).
// metrics is served at /metrics.
func (h *Handlers) RegisterInternal(mux *nethttp.ServeMux, metrics nethttp.Handler) {
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /readyz", h.readyz)
	if metrics != nil {
		mux.Handle("GET /metrics", metrics)
	}
	mux.HandleFunc("POST /internal/v1/verify-password", h.internalOnly(h.internalVerifyPassword))
}

func (h *Handlers) internalOnly(next nethttp.HandlerFunc) nethttp.HandlerFunc {
	want := h.Config.InternalConfig.APIToken
	wantSum := sha256.Sum256([]byte(want))
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if want == "" {
			writeError(w, r, apperr.New(nethttp.StatusServiceUnavailable, "internal_api_disabled", "INTERNAL_API_TOKEN is not configured"))
			return
		}
		got := sha256.Sum256([]byte(r.Header.Get(InternalTokenHeader)))
		if subtle.ConstantTimeCompare(got[:], wantSum[:]) != 1 {
			writeError(w, r, apperr.ErrUnauthenticated)
			return
		}
		// The caller proved INTERNAL_API_TOKEN, so it is trusted to tell us the
		// end user's address (e.g. the IRC client behind Ergo). Use it for rate
		// limits and the audit log/sessions.
		if ip, ok := ForwardedClientIP(r); ok {
			m := reqmeta.From(r.Context())
			m.IP = ip
			r = r.WithContext(reqmeta.With(r.Context(), m))
		}
		next(w, r)
	}
}

type verifyPasswordReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type verifyPasswordResp struct {
	OK       bool   `json:"ok"`
	UserID   string `json:"user_id,omitempty"`
	Username string `json:"username,omitempty"`
	// Reason is set when ok is false: invalid_credentials | account_disabled | email_not_verified.
	Reason string `json:"reason,omitempty"`
}

func (h *Handlers) internalVerifyPassword(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req verifyPasswordReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if _, forwarded := ForwardedClientIP(r); forwarded {
		if !h.Limits.allow(w, r, BucketInternalIP, "") {
			return
		}
	}
	if !h.Limits.allow(w, r, BucketInternal, accountKey(req.Username)) {
		return
	}
	u, err := h.Authn.VerifyPassword(r.Context(), req.Username, req.Password)
	if err != nil {
		if e, ok := apperr.As(err); ok && e.Status < 500 {
			writeJSON(w, nethttp.StatusOK, verifyPasswordResp{OK: false, Reason: e.Code})
			return
		}
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, verifyPasswordResp{OK: true, UserID: u.ID, Username: u.Username})
}

// ForwardedClientIP returns the end-user IP an internal caller forwarded in
// X-Forwarded-For (the leftmost entry, i.e. the original client). Only call it
// for requests that already passed the internal token check.
func ForwardedClientIP(r *nethttp.Request) (string, bool) {
	v := r.Header.Get("X-Forwarded-For")
	if v == "" {
		return "", false
	}
	first, _, _ := strings.Cut(v, ",")
	a, err := netip.ParseAddr(strings.TrimSpace(first))
	if err != nil {
		return "", false
	}
	return a.Unmap().String(), true
}
