package handlers

import (
	"context"
	"errors"
	nethttp "net/http"
	"strings"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/services/account"
	"github.com/boson-chat/auth/internal/services/admin"
	"github.com/boson-chat/auth/internal/services/authn"
	"github.com/boson-chat/auth/internal/services/idp"
	"github.com/boson-chat/auth/internal/services/keys"
	"github.com/boson-chat/auth/internal/services/session"
	"github.com/boson-chat/auth/internal/textutil"
)

const (
	AccessCookie  = "boson_at"
	RefreshCookie = "boson_rt"
	// CSRFHeader must be present on state-changing requests that rely on
	// cookies. Browsers only let same-origin (or CORS-allowed) scripts set it.
	CSRFHeader = "X-Requested-With"
)

var errCSRF = apperr.New(nethttp.StatusForbidden, "csrf", "cookie-authenticated requests must send the X-Requested-With header")

// Handlers is the DI container for the HTTP layer.
type Handlers struct {
	Account  account.AccountServiceImpl
	Authn    authn.AuthnServiceImpl
	Sessions session.SessionServiceImpl
	Admin    admin.AdminServiceImpl
	Keys     keys.KeyServiceImpl
	IdP      idp.IdPServiceImpl
	Limits   *Limits
	Config   config.Config
	// Ready reports whether dependencies (database) are reachable.
	Ready func(ctx context.Context) error
}

type principalKey struct{}

func principalFrom(r *nethttp.Request) *authn.Principal {
	p, _ := r.Context().Value(principalKey{}).(*authn.Principal)
	return p
}

func unsafeMethod(m string) bool {
	return m != nethttp.MethodGet && m != nethttp.MethodHead && m != nethttp.MethodOptions
}

func requireCSRFHeader(r *nethttp.Request) error {
	if r.Header.Get(CSRFHeader) == "" {
		return errCSRF
	}
	return nil
}

// bearer returns the access token and whether it came from a cookie.
func bearer(r *nethttp.Request) (string, bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		if tok, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(tok), false
		}
		return "", false
	}
	if c, err := r.Cookie(AccessCookie); err == nil {
		return c.Value, true
	}
	return "", false
}

// authed wraps a handler that needs a logged-in user.
func (h *Handlers) authed(next nethttp.HandlerFunc) nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		tok, viaCookie := bearer(r)
		if viaCookie && unsafeMethod(r.Method) {
			if err := requireCSRFHeader(r); err != nil {
				writeError(w, r, err)
				return
			}
		}
		p, err := h.Authn.Authenticate(r.Context(), tok)
		if err != nil {
			if errors.Is(err, apperr.ErrAccountDisabled) {
				err = apperr.ErrUnauthenticated
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="boson"`)
			writeError(w, r, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	}
}

// adminOnly wraps a handler that needs role=admin (checked against the DB).
func (h *Handlers) adminOnly(next nethttp.HandlerFunc) nethttp.HandlerFunc {
	return h.authed(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if !principalFrom(r).IsAdmin() {
			writeError(w, r, apperr.ErrForbidden)
			return
		}
		if id := r.PathValue("id"); id != "" && !textutil.Storable(id) {
			writeError(w, r, apperr.ErrNotFound)
			return
		}
		next(w, r)
	})
}

func (h *Handlers) setCookie(w nethttp.ResponseWriter, name, value, path string, expires time.Time) {
	c := &nethttp.Cookie{
		Name: name, Value: value, Path: path, Domain: h.Config.HTTPConfig.CookieDomain,
		HttpOnly: true, Secure: h.Config.HTTPConfig.CookieSecure, SameSite: nethttp.SameSiteLaxMode,
	}
	if value == "" {
		c.MaxAge = -1
	} else {
		c.Expires = expires
		c.MaxAge = int(time.Until(expires).Seconds())
	}
	nethttp.SetCookie(w, c)
}

func (h *Handlers) setTokenCookies(w nethttp.ResponseWriter, t *authn.Tokens) {
	h.setCookie(w, AccessCookie, t.AccessToken, "/", t.AccessExpiresAt)
	h.setCookie(w, RefreshCookie, t.RefreshToken, "/v1", t.RefreshExpiresAt)
}

func (h *Handlers) clearTokenCookies(w nethttp.ResponseWriter) {
	h.setCookie(w, AccessCookie, "", "/", time.Time{})
	h.setCookie(w, RefreshCookie, "", "/v1", time.Time{})
}

type tokenResponse struct {
	TokenType        string   `json:"token_type"`
	AccessToken      string   `json:"access_token,omitempty"`
	ExpiresIn        int64    `json:"expires_in"`
	RefreshToken     string   `json:"refresh_token,omitempty"`
	RefreshExpiresIn int64    `json:"refresh_expires_in"`
	SessionID        string   `json:"session_id"`
	User             userJSON `json:"user"`
}

// respondTokens returns tokens in the body, or (cookie mode) only in
// HttpOnly cookies so page scripts never see them.
func (h *Handlers) respondTokens(w nethttp.ResponseWriter, t *authn.Tokens, cookie bool) {
	now := time.Now()
	resp := tokenResponse{
		TokenType:        "Bearer",
		ExpiresIn:        int64(t.AccessExpiresAt.Sub(now).Seconds()),
		RefreshExpiresIn: int64(t.RefreshExpiresAt.Sub(now).Seconds()),
		SessionID:        t.Session.ID,
		User:             toUser(t.User),
	}
	if cookie {
		h.setTokenCookies(w, t)
	} else {
		resp.AccessToken, resp.RefreshToken = t.AccessToken, t.RefreshToken
	}
	writeJSON(w, nethttp.StatusOK, resp)
}
