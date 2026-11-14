package handlers

import (
	nethttp "net/http"

	"github.com/boson-chat/auth/internal/perm"
	"github.com/boson-chat/auth/internal/services/email"
)

// registerEmail mounts the email preview / test endpoints for the admin
// panel on the internal listener. They need a user's access token with
// settings.manage, like PATCH /v1/admin/settings.
func (h *Handlers) registerEmail(mux *nethttp.ServeMux) {
	if h.Email == nil {
		return
	}
	manage := h.allow(perm.SettingsManage)
	mux.HandleFunc("POST /internal/email/preview", manage(h.emailPreview))
	mux.HandleFunc("POST /internal/email/test", manage(h.emailTest))
}

type emailPreviewReq struct {
	Template string  `json:"template"`
	Subject  *string `json:"subject"`
	Body     *string `json:"body"`
	// Email: unsaved auth.email settings; absent fields keep the saved ones.
	Email *struct {
		SenderName *string `json:"sender_name"`
		Accent     *string `json:"accent"`
		Footer     *string `json:"footer"`
		Logo       *bool   `json:"logo"`
	} `json:"email"`
}

// emailPreview: {template, subject?, body?, email?: {sender_name?, accent?,
// footer?, logo?}} → {subject, html, text, from}, the email as it would be
// sent now with the unsaved values on top. Called while the admin types,
// so it is cheap (cached, rate-limited generously per admin).
func (h *Handlers) emailPreview(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req emailPreviewReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	p := principalFrom(r)
	if !h.Limits.allow(w, r, BucketEmailPreview, p.UserID) {
		return
	}
	in := email.PreviewInput{Template: req.Template, Subject: req.Subject, Body: req.Body}
	if e := req.Email; e != nil {
		in.Email = &email.EmailOverrides{SenderName: e.SenderName, Accent: e.Accent, Footer: e.Footer, Logo: e.Logo}
	}
	out, err := h.Email.Preview(r.Context(), p.User.Username, in)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, out)
}

type emailTestReq struct {
	Template string `json:"template"`
	To       string `json:"to"`
}

type emailTestResp struct {
	// Status: "sent" (handed to the SMTP server) or "logged" (no SMTP_HOST:
	// written to auth's log only).
	Status  string `json:"status"`
	To      string `json:"to"`
	Subject string `json:"subject"`
}

// emailTest: {template, to} sends the email with sample values now.
// Rate-limited per admin (BucketEmailTest) and audited (email_test_sent).
func (h *Handlers) emailTest(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req emailTestReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	p := principalFrom(r)
	if !h.Limits.allow(w, r, BucketEmailTest, p.UserID) {
		return
	}
	out, err := h.Email.SendTest(r.Context(), p.UserID, req.Template, p.User.Username, req.To)
	if err != nil {
		writeError(w, r, err)
		return
	}
	status := "sent"
	if h.Email.Logging() {
		status = "logged"
	}
	writeJSON(w, nethttp.StatusOK, emailTestResp{Status: status, To: req.To, Subject: out.Subject})
}
