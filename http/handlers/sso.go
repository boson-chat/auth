package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"html/template"
	nethttp "net/http"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories/identity"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/services/sso"
)

// SSOStateCookie carries the encrypted state of one SSO login flow.
const (
	SSOStateCookie = "boson_sso"
	ssoCookiePath  = "/v1/sso/"
	maxACSBody     = 1 << 20
)

func (h *Handlers) registerSSO(mux *nethttp.ServeMux) {
	mux.HandleFunc("GET /v1/sso/{slug}/start", h.ssoStart)
	mux.HandleFunc("GET /v1/sso/{slug}/callback", h.ssoCallback)
	mux.HandleFunc("POST /v1/sso/{slug}/saml/acs", h.ssoACS)
	mux.HandleFunc("GET /v1/sso/{slug}/saml/metadata", h.ssoMetadata)
	mux.HandleFunc("POST /v1/sso/exchange", h.ssoExchange)

	mux.HandleFunc("GET /v1/me/identities", h.authed(h.listMyIdentities))
	mux.HandleFunc("DELETE /v1/me/identities/{id}", h.authed(h.unlinkMyIdentity))

	mux.HandleFunc("GET /v1/admin/sso/providers", h.adminOnly(h.adminListProviders))
	mux.HandleFunc("POST /v1/admin/sso/providers", h.adminOnly(h.adminCreateProvider))
	mux.HandleFunc("GET /v1/admin/sso/providers/{id}", h.adminOnly(h.adminGetProvider))
	mux.HandleFunc("PATCH /v1/admin/sso/providers/{id}", h.adminOnly(h.adminUpdateProvider))
	mux.HandleFunc("DELETE /v1/admin/sso/providers/{id}", h.adminOnly(h.adminDeleteProvider))
	mux.HandleFunc("POST /v1/admin/sso/providers/{id}/test", h.adminOnly(h.adminTestProvider))
}

func (h *Handlers) setSSOCookie(w nethttp.ResponseWriter, value string, crossSitePost bool) {
	c := &nethttp.Cookie{
		Name: SSOStateCookie, Value: value, Path: ssoCookiePath, Domain: h.Config.HTTPConfig.CookieDomain,
		HttpOnly: true, Secure: h.Config.HTTPConfig.CookieSecure, SameSite: nethttp.SameSiteLaxMode,
	}
	// SAML IdPs return with a cross-site POST, which never carries Lax
	// cookies. None requires Secure, so plain-http dev stays on Lax.
	if crossSitePost && c.Secure {
		c.SameSite = nethttp.SameSiteNoneMode
	}
	if value == "" {
		c.MaxAge = -1
	} else {
		c.MaxAge = int(h.Config.SSOConfig.StateTTL.Seconds())
	}
	nethttp.SetCookie(w, c)
}

// redirectError sends the browser back to a validated return_to with
// ?error=<code>&error_description=<text>.
func redirectError(w nethttp.ResponseWriter, r *nethttp.Request, returnTo string, err error) {
	code, msg := "server_error", "something went wrong; please try again"
	if e, ok := apperr.As(err); ok {
		code, msg = e.Code, e.Message
	} else {
		logger.FromCtx(r.Context()).Error().Err(err).Str("path", r.URL.Path).Msg("sso error")
	}
	nethttp.Redirect(w, r, sso.WithParams(returnTo, "error", code, "error_description", msg), nethttp.StatusSeeOther)
}

var postFormTmpl = template.Must(template.New("post").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Signing in…</title></head><body>
<form method="post" action="{{.URL}}" id="f">{{range $k, $v := .Fields}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
<noscript><button type="submit">Continue</button></noscript></form>
<script nonce="{{.Nonce}}">document.getElementById("f").submit()</script>
</body></html>`))

func (h *Handlers) ssoStart(w nethttp.ResponseWriter, r *nethttp.Request) {
	if !h.Limits.allow(w, r, BucketSSO, "") {
		return
	}
	q := r.URL.Query()
	res, err := h.SSO.Start(r.Context(), sso.StartInput{
		Slug: r.PathValue("slug"), ReturnTo: q.Get("return_to"), Mode: q.Get("mode"), InviteCode: q.Get("invite_code"),
		CodeChallenge: q.Get("code_challenge"), CodeChallengeMethod: q.Get("code_challenge_method"),
	})
	if err != nil {
		if res != nil && res.ReturnTo != "" {
			redirectError(w, r, res.ReturnTo, err)
			return
		}
		writeError(w, r, err)
		return
	}
	h.setSSOCookie(w, res.Cookie, res.Kind == identity.KindSAML)
	if res.Login.RedirectURL != "" {
		nethttp.Redirect(w, r, res.Login.RedirectURL, nethttp.StatusFound)
		return
	}
	nb := make([]byte, 18)
	_, _ = rand.Read(nb)
	nonce := base64.RawStdEncoding.EncodeToString(nb)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; base-uri 'none'; frame-ancestors 'none'")
	_ = postFormTmpl.Execute(w, map[string]any{"URL": res.Login.PostURL, "Fields": res.Login.PostFields, "Nonce": nonce})
}

func (h *Handlers) ssoCallback(w nethttp.ResponseWriter, r *nethttp.Request) {
	h.ssoFinish(w, r, r.URL.Query().Get("state"))
}

func (h *Handlers) ssoACS(w nethttp.ResponseWriter, r *nethttp.Request) {
	r.Body = nethttp.MaxBytesReader(w, r.Body, maxACSBody)
	if err := r.ParseForm(); err != nil {
		writeError(w, r, apperr.Invalid("malformed SAML response"))
		return
	}
	h.ssoFinish(w, r, r.PostForm.Get("RelayState"))
}

func (h *Handlers) ssoFinish(w nethttp.ResponseWriter, r *nethttp.Request, stateParam string) {
	if !h.Limits.allow(w, r, BucketSSO, "") {
		return
	}
	cookie := ""
	if c, err := r.Cookie(SSOStateCookie); err == nil {
		cookie = c.Value
	}
	h.setSSOCookie(w, "", false) // single use
	res, err := h.SSO.Complete(r.Context(), r.PathValue("slug"), r, stateParam, cookie)
	if err != nil {
		if res != nil && res.ReturnTo != "" {
			redirectError(w, r, res.ReturnTo, err)
			return
		}
		writeError(w, r, err)
		return
	}
	if res.Tokens != nil {
		h.setTokenCookies(w, res.Tokens)
		nethttp.Redirect(w, r, res.ReturnTo, nethttp.StatusSeeOther)
		return
	}
	nethttp.Redirect(w, r, sso.WithParams(res.ReturnTo, "code", res.Code), nethttp.StatusSeeOther)
}

func (h *Handlers) ssoMetadata(w nethttp.ResponseWriter, r *nethttp.Request) {
	md, err := h.SSO.SAMLMetadata(r.Context(), r.PathValue("slug"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(md)
}

type exchangeReq struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	Cookie       bool   `json:"cookie"`
}

func (h *Handlers) ssoExchange(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req exchangeReq
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
	if !h.Limits.allow(w, r, BucketSSOExchange, "") {
		return
	}
	t, err := h.SSO.Exchange(r.Context(), req.Code, req.CodeVerifier)
	if err != nil {
		writeError(w, r, err)
		return
	}
	h.respondTokens(w, t, req.Cookie)
}

type identityJSON struct {
	ID                  string     `json:"id"`
	ProviderID          string     `json:"provider_id"`
	ProviderSlug        string     `json:"provider_slug"`
	ProviderKind        string     `json:"provider_kind"`
	ProviderDisplayName string     `json:"provider_display_name"`
	Subject             string     `json:"subject"`
	Email               *string    `json:"email"`
	CreatedAt           time.Time  `json:"created_at"`
	LastLoginAt         *time.Time `json:"last_login_at"`
}

func toIdentities(list []*identity.IdentityView) []identityJSON {
	out := make([]identityJSON, 0, len(list))
	for _, i := range list {
		out = append(out, identityJSON{
			ID: i.ID, ProviderID: i.ProviderID, ProviderSlug: i.ProviderSlug, ProviderKind: i.ProviderKind,
			ProviderDisplayName: i.ProviderDisplayName, Subject: i.Subject, Email: i.Email,
			CreatedAt: i.CreatedAt, LastLoginAt: i.LastLoginAt,
		})
	}
	return out
}

func (h *Handlers) listMyIdentities(w nethttp.ResponseWriter, r *nethttp.Request) {
	p := principalFrom(r)
	list, err := h.SSO.ListIdentities(r.Context(), p.UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	hasPW, err := h.SSO.HasPassword(r.Context(), p.UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"identities": toIdentities(list), "has_password": hasPW})
}

func (h *Handlers) unlinkMyIdentity(w nethttp.ResponseWriter, r *nethttp.Request) {
	if err := h.SSO.UnlinkIdentity(r.Context(), principalFrom(r).UserID, r.PathValue("id")); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(nethttp.StatusNoContent)
}

type providerJSON struct {
	ID              string         `json:"id"`
	Slug            string         `json:"slug"`
	Kind            string         `json:"kind"`
	DisplayName     string         `json:"display_name"`
	Enabled         bool           `json:"enabled"`
	AllowSignup     bool           `json:"allow_signup"`
	TrustEmail      bool           `json:"trust_email"`
	Config          map[string]any `json:"config"`
	HasClientSecret bool           `json:"has_client_secret"`
	StartURL        string         `json:"start_url"`
	RedirectURI     string         `json:"redirect_uri,omitempty"`
	ACSURL          string         `json:"acs_url,omitempty"`
	SPMetadataURL   string         `json:"sp_metadata_url,omitempty"`
	SPEntityID      string         `json:"sp_entity_id,omitempty"`
	SPCertificate   string         `json:"sp_certificate,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func toProvider(v *sso.ProviderView) providerJSON {
	cfg := map[string]any{}
	for k, val := range v.Config {
		cfg[k] = val
	}
	if v.Kind == identity.KindOIDC {
		cfg["has_client_secret"] = v.HasClientSecret
	}
	return providerJSON{
		ID: v.ID, Slug: v.Slug, Kind: v.Kind, DisplayName: v.DisplayName, Enabled: v.Enabled,
		AllowSignup: v.AllowSignup, TrustEmail: v.TrustEmail, Config: cfg, HasClientSecret: v.HasClientSecret,
		StartURL: v.StartURL, RedirectURI: v.RedirectURI, ACSURL: v.ACSURL, SPMetadataURL: v.SPMetadataURL,
		SPEntityID: v.SPEntityID, SPCertificate: v.SPCert, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt,
	}
}

type providerReq struct {
	Slug        *string        `json:"slug"`
	Kind        *string        `json:"kind"`
	DisplayName *string        `json:"display_name"`
	Enabled     *bool          `json:"enabled"`
	AllowSignup *bool          `json:"allow_signup"`
	TrustEmail  *bool          `json:"trust_email"`
	Config      map[string]any `json:"config"`
}

func (p providerReq) input() sso.ProviderInput {
	return sso.ProviderInput{Slug: p.Slug, Kind: p.Kind, DisplayName: p.DisplayName, Enabled: p.Enabled,
		AllowSignup: p.AllowSignup, TrustEmail: p.TrustEmail, Config: p.Config}
}

func (h *Handlers) adminListProviders(w nethttp.ResponseWriter, r *nethttp.Request) {
	list, err := h.SSO.ListProviders(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := make([]providerJSON, 0, len(list))
	for _, v := range list {
		out = append(out, toProvider(v))
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"providers": out})
}

func (h *Handlers) adminGetProvider(w nethttp.ResponseWriter, r *nethttp.Request) {
	v, err := h.SSO.GetProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"provider": toProvider(v)})
}

func (h *Handlers) adminCreateProvider(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req providerReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	v, err := h.SSO.CreateProvider(r.Context(), principalFrom(r).UserID, req.input())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusCreated, map[string]any{"provider": toProvider(v)})
}

func (h *Handlers) adminUpdateProvider(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req providerReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	v, err := h.SSO.UpdateProvider(r.Context(), principalFrom(r).UserID, r.PathValue("id"), req.input())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"provider": toProvider(v)})
}

func (h *Handlers) adminDeleteProvider(w nethttp.ResponseWriter, r *nethttp.Request) {
	if err := h.SSO.DeleteProvider(r.Context(), principalFrom(r).UserID, r.PathValue("id")); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(nethttp.StatusNoContent)
}

func (h *Handlers) adminTestProvider(w nethttp.ResponseWriter, r *nethttp.Request) {
	ok, details, err := h.SSO.TestProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"ok": ok, "details": details})
}
