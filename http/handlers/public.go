package handlers

import (
	"context"
	"encoding/json"
	nethttp "net/http"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/services/account"
	"github.com/boson-chat/auth/internal/services/idp"
	"github.com/boson-chat/auth/internal/services/keys"
	"github.com/boson-chat/auth/internal/services/token"
)

// RegisterPublic mounts the public API.
func (h *Handlers) RegisterPublic(mux *nethttp.ServeMux) {
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /readyz", h.readyz)
	mux.HandleFunc("GET /version", h.version)
	mux.HandleFunc("GET /.well-known/jwks.json", h.jwks)
	mux.HandleFunc("GET /.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("GET /v1/config", h.publicConfig)

	mux.HandleFunc("POST /v1/register", h.register)
	mux.HandleFunc("POST /v1/register/confirm", h.confirmRegistration)
	mux.HandleFunc("POST /v1/email/verify", h.verifyEmail)
	mux.HandleFunc("POST /v1/email/resend", h.resendVerification)
	mux.HandleFunc("POST /v1/login", h.login)
	mux.HandleFunc("POST /v1/token/refresh", h.refresh)
	mux.HandleFunc("POST /v1/logout", h.logout)
	mux.HandleFunc("POST /v1/password/forgot", h.forgotPassword)
	mux.HandleFunc("POST /v1/password/reset", h.resetPassword)

	mux.HandleFunc("POST /v1/password/change", h.authed(h.changePassword))
	mux.HandleFunc("GET /v1/me", h.authed(h.me))
	mux.HandleFunc("PATCH /v1/me", h.authed(h.updateMe))
	mux.HandleFunc("GET /v1/sessions", h.authed(h.listSessions))
	mux.HandleFunc("DELETE /v1/sessions/{id}", h.authed(h.revokeSession))
	mux.HandleFunc("POST /v1/voice/token", h.authed(h.voiceToken))
	mux.HandleFunc("POST /v1/voice/guest-token", h.guestVoiceToken)

	h.registerFederation(mux)
	h.registerWorkloadPublic(mux)
	h.registerSocial(mux)
	h.registerBranding(mux)
	h.registerSSO(mux)
	h.registerAdmin(mux)
	h.registerPages(mux)
}

func (h *Handlers) healthz(w nethttp.ResponseWriter, _ *nethttp.Request) {
	writeJSON(w, nethttp.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handlers) readyz(w nethttp.ResponseWriter, r *nethttp.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if h.Ready != nil {
		if err := h.Ready(ctx); err != nil {
			writeJSON(w, nethttp.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
	}
	if _, _, err := h.Keys.SigningKey(ctx); err != nil {
		writeJSON(w, nethttp.StatusServiceUnavailable, map[string]string{"status": "no signing key"})
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handlers) jwks(w nethttp.ResponseWriter, r *nethttp.Request) {
	set := h.Keys.JWKS(r.Context())
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(nethttp.StatusOK)
	_ = json.NewEncoder(w).Encode(set)
}

func (h *Handlers) discovery(w nethttp.ResponseWriter, _ *nethttp.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, nethttp.StatusOK, map[string]any{
		"issuer":                                h.Config.TokenConfig.Issuer,
		"jwks_uri":                              h.Config.HTTPConfig.PublicURL + "/.well-known/jwks.json",
		"id_token_signing_alg_values_supported": []string{keys.AlgEdDSA},
		"subject_types_supported":               []string{"public"},
	})
}

func (h *Handlers) publicConfig(w nethttp.ResponseWriter, r *nethttp.Request) {
	providers := []idp.ProviderInfo{}
	if h.SSO != nil {
		providers = h.SSO.Providers(r.Context())
	}
	st, err := h.Settings.Get(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	// The network's theme (GET /v1/branding); null without branding.
	var brandingURL *string
	if h.Branding != nil {
		if u := h.Branding.URL(); u != "" {
			brandingURL = &u
		}
	}
	// The network's files (uploads) service; null when there is none or
	// uploads are off.
	var filesURL *string
	u := h.Config.FilesConfig.URL()
	if h.FilesURL != nil {
		u = h.FilesURL()
	}
	if u != "" {
		filesURL = &u
	}
	// The network's name (SITE_NAME / network.name); null when unset.
	var networkName *string
	name := h.Config.AppConfig.NetworkName()
	if h.NetworkName != nil {
		name = h.NetworkName()
	}
	if name != "" {
		networkName = &name
	}
	// The network channels (config irc.channels).
	channels := h.Config.IRCConfig.Channels
	if h.NetworkChannels != nil {
		channels = h.NetworkChannels()
	}
	type publicChannel struct {
		config.NetworkChannel
		// Restricted: only some roles may join (which ones isn't public).
		Restricted bool `json:"restricted,omitempty"`
	}
	public := make([]publicChannel, 0, len(channels))
	for _, c := range channels {
		public = append(public, publicChannel{NetworkChannel: c, Restricted: c.Restricted()})
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{
		"registration":               st.Registration,
		"require_email_verification": st.RequireEmailVerification,
		"channel_creation":           st.ChannelCreation,
		"voice_channel_creation":     st.VoiceChannelCreation,
		"channel_auto_register":      st.ChannelAutoRegister,
		"channel_expiry_days":        st.ChannelExpiryDays,
		"guest_access":               st.GuestAccess,
		// Guests may join voice: only when guests may connect at all.
		"guest_voice":   st.GuestAccess && st.GuestVoice,
		"sso_providers": providers,
		"network_name":  networkName,
		"branding_url":  brandingURL,
		"files_url":     filesURL,
		"channels":      public,
		"accounts":      h.accountsInfo(),
	})
}

// accountsInfo is GET /v1/config's accounts: where accounts live and what
// sign-up / password reset do there.
func (h *Handlers) accountsInfo() map[string]any {
	if h.NickServ == nil {
		return map[string]any{"backend": config.AccountBackendLocal, "signup": true, "signup_message": nil, "password_reset": true}
	}
	su := h.NickServ.Signup()
	var msg *string
	if su.Message != "" {
		msg = &su.Message
	}
	return map[string]any{"backend": config.AccountBackendNickServ, "signup": su.Available, "signup_message": msg, "password_reset": false}
}

type registerReq struct {
	Username   string `json:"username"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	InviteCode string `json:"invite_code"`
	// ReturnTo: where the verification link's page sends the user after
	// verifying (dropped unless allowed, see verifyReturnTo).
	ReturnTo string `json:"return_to"`
}

func (h *Handlers) register(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req registerReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if !h.Limits.allow(w, r, BucketRegister, accountKey(req.Email)) {
		return
	}
	res, err := h.Account.Register(r.Context(), account.RegisterInput{
		Username: req.Username, Email: req.Email, Password: req.Password, InviteCode: req.InviteCode,
		ReturnTo: h.verifyReturnTo(req.ReturnTo),
	})
	if err != nil {
		writeError(w, r, err)
		return
	}
	st, err := h.Settings.Get(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := map[string]any{
		"user":                        toUser(res.User),
		"email_verification_sent":     res.Verification != "",
		"email_verification_required": st.RequireEmailVerification && res.Verification != "",
	}
	if h.NickServ != nil {
		// NickServ backend: the services verify (a code to confirm with
		// POST /v1/register/confirm), or nothing needs verifying.
		out["verification"] = res.Verification
		out["message"] = res.Message
	}
	writeJSON(w, nethttp.StatusCreated, out)
}

type confirmRegistrationReq struct {
	Username string `json:"username"`
	// Password: Atheme 7.2 only takes the code from the account itself.
	Password string `json:"password"`
	Code     string `json:"code"`
}

// confirmRegistration submits the code NickServ emailed after sign-up.
func (h *Handlers) confirmRegistration(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req confirmRegistrationReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if !h.Limits.allow(w, r, BucketVerify, accountKey(req.Username)) {
		return
	}
	if err := h.Account.ConfirmRegistration(r.Context(), req.Username, req.Password, req.Code); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]string{"status": "registration confirmed; you can sign in now"})
}

type tokenReq struct {
	Token string `json:"token"`
}

type verifyReq struct {
	Token string `json:"token"`
	// ReturnTo: the link's ?return_to=, checked again here (the link may
	// have been edited).
	ReturnTo string `json:"return_to"`
}

func (h *Handlers) verifyEmail(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req verifyReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if !h.Limits.allow(w, r, BucketVerify, "") {
		return
	}
	u, err := h.Account.VerifyEmail(r.Context(), req.Token)
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := map[string]any{"user": toUser(u)}
	if to := h.verifiedRedirect(req.ReturnTo); to != "" {
		out["redirect_to"] = to
	}
	writeJSON(w, nethttp.StatusOK, out)
}

type emailReq struct {
	Email string `json:"email"`
}

type resendReq struct {
	Email    string `json:"email"`
	ReturnTo string `json:"return_to"` // as registerReq.ReturnTo
}

func (h *Handlers) resendVerification(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req resendReq
	if err := decodeOptional(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	userID := ""
	if tok, viaCookie := bearer(r); tok != "" {
		if viaCookie {
			if err := requireCSRFHeader(r); err != nil {
				writeError(w, r, err)
				return
			}
		}
		if p, err := h.Authn.Authenticate(r.Context(), tok); err == nil {
			userID = p.UserID
		}
	}
	key := accountKey(req.Email)
	if userID != "" {
		key = "id:" + userID
	}
	if !h.Limits.allow(w, r, BucketVerify, key) {
		return
	}
	if err := h.Account.ResendVerification(r.Context(), userID, req.Email, h.verifyReturnTo(req.ReturnTo)); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusAccepted, map[string]string{"status": "if the account exists and is unverified, a new link has been sent"})
}

type loginReq struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	// Cookie: return tokens as HttpOnly cookies instead of in the body.
	Cookie bool `json:"cookie"`
}

func (h *Handlers) login(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req loginReq
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
	if !h.Limits.allow(w, r, BucketLogin, accountKey(req.Login)) {
		return
	}
	t, err := h.Authn.Login(r.Context(), req.Login, req.Password)
	if err != nil {
		writeError(w, r, err)
		return
	}
	h.respondTokens(w, t, req.Cookie)
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

// refreshToken reads the token from the body, falling back to the cookie
// (which then requires the CSRF header).
func (h *Handlers) refreshToken(w nethttp.ResponseWriter, r *nethttp.Request) (string, bool, error) {
	var req refreshReq
	if err := decodeOptional(w, r, &req); err != nil {
		return "", false, err
	}
	if req.RefreshToken != "" {
		return req.RefreshToken, false, nil
	}
	c, err := r.Cookie(RefreshCookie)
	if err != nil || c.Value == "" {
		return "", false, nil
	}
	if err := requireCSRFHeader(r); err != nil {
		return "", true, err
	}
	return c.Value, true, nil
}

func (h *Handlers) refresh(w nethttp.ResponseWriter, r *nethttp.Request) {
	raw, viaCookie, err := h.refreshToken(w, r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	t, err := h.Authn.Refresh(r.Context(), raw)
	if err != nil {
		if viaCookie {
			h.clearTokenCookies(w)
		}
		writeError(w, r, err)
		return
	}
	h.respondTokens(w, t, viaCookie)
}

func (h *Handlers) logout(w nethttp.ResponseWriter, r *nethttp.Request) {
	tok, viaCookie := bearer(r)
	if viaCookie {
		if err := requireCSRFHeader(r); err != nil {
			writeError(w, r, err)
			return
		}
	}
	if p, err := h.Authn.Authenticate(r.Context(), tok); err == nil {
		if err := h.Authn.Logout(r.Context(), p); err != nil {
			writeError(w, r, err)
			return
		}
	} else {
		// Expired access token: identify the session by its refresh token.
		raw, _, err := h.refreshToken(w, r)
		if err != nil {
			writeError(w, r, err)
			return
		}
		if raw == "" {
			writeError(w, r, apperr.ErrUnauthenticated)
			return
		}
		userID, _, err := h.Sessions.RevokeByRefreshToken(r.Context(), raw)
		if err != nil {
			writeError(w, r, err)
			return
		}
		if h.NickServ != nil && userID != "" {
			h.NickServ.EndSession(r.Context(), userID)
		}
	}
	h.clearTokenCookies(w)
	w.WriteHeader(nethttp.StatusNoContent)
}

func (h *Handlers) forgotPassword(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req emailReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if !h.Limits.allow(w, r, BucketForgot, accountKey(req.Email)) {
		return
	}
	if err := h.Account.ForgotPassword(r.Context(), req.Email); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusAccepted, map[string]string{"status": "if an account uses that address, a reset link has been sent to it"})
}

type resetReq struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (h *Handlers) resetPassword(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req resetReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if !h.Limits.allow(w, r, BucketReset, "") {
		return
	}
	if err := h.Account.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		writeError(w, r, err)
		return
	}
	h.clearTokenCookies(w)
	writeJSON(w, nethttp.StatusOK, map[string]string{"status": "password changed; all sessions signed out"})
}

type changeReq struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

func (h *Handlers) changePassword(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req changeReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	p := principalFrom(r)
	if !h.Limits.allow(w, r, BucketLogin, "id:"+p.UserID) {
		return
	}
	if err := h.Account.ChangePassword(r.Context(), p.UserID, p.SessionID, req.Current, req.New); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]string{"status": "password changed; other sessions signed out"})
}

func (h *Handlers) me(w nethttp.ResponseWriter, r *nethttp.Request) {
	p := principalFrom(r)
	a, err := h.Roles.Access(r.Context(), p.UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := map[string]any{
		"user": toUser(p.User), "session_id": p.SessionID,
		"roles": toRoleSummaries(a.Assigned()), "permissions": a.Permissions,
	}
	if h.Federation != nil {
		// federation: {identity, home_domain, issuer} for an account of
		// another Boson server, null for a local one.
		fa, err := h.Federation.Account(r.Context(), p.UserID)
		if err != nil {
			writeError(w, r, err)
			return
		}
		out["federation"] = toFederation(fa)
	}
	writeJSON(w, nethttp.StatusOK, out)
}

type updateMeReq struct {
	DisplayName *string `json:"display_name"`
}

func (h *Handlers) updateMe(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req updateMeReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	u, err := h.Account.UpdateProfile(r.Context(), principalFrom(r).UserID, req.DisplayName)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"user": toUser(u)})
}

func (h *Handlers) listSessions(w nethttp.ResponseWriter, r *nethttp.Request) {
	p := principalFrom(r)
	list, err := h.Sessions.ListActive(r.Context(), p.UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	out := make([]sessionJSON, 0, len(list))
	for _, s := range list {
		out = append(out, toSession(s, p.SessionID, false))
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"sessions": out})
}

func (h *Handlers) revokeSession(w nethttp.ResponseWriter, r *nethttp.Request) {
	p := principalFrom(r)
	id := r.PathValue("id")
	if err := h.Sessions.Revoke(r.Context(), p.UserID, id); err != nil {
		writeError(w, r, err)
		return
	}
	if id == p.SessionID {
		h.clearTokenCookies(w)
	}
	w.WriteHeader(nethttp.StatusNoContent)
}

type voiceReq struct {
	Rooms []string `json:"rooms"`
}

func (h *Handlers) voiceToken(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req voiceReq
	if err := decodeOptional(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	tok, exp, err := h.Authn.VoiceToken(r.Context(), principalFrom(r), req.Rooms)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{
		"token":      tok,
		"expires_in": int64(time.Until(exp).Seconds()),
		"audience":   token.AudienceQuicvoice,
	})
}

type guestVoiceReq struct {
	Nick    string   `json:"nick"`
	GuestID string   `json:"guest_id"`
	Rooms   []string `json:"rooms"`
}

// guestVoiceToken: POST /v1/voice/guest-token, no auth. A voice token for an
// IRC guest under its (unverified) nick; see authn.GuestVoiceToken.
func (h *Handlers) guestVoiceToken(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req guestVoiceReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if !h.Limits.allow(w, r, BucketGuestVoice, "") {
		return
	}
	tok, exp, err := h.Authn.GuestVoiceToken(r.Context(), req.Nick, req.GuestID, req.Rooms)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{
		"token":      tok,
		"expires_in": int64(time.Until(exp).Seconds()),
		"audience":   token.AudienceQuicvoice,
	})
}
