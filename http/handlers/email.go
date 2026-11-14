package handlers

import (
	nethttp "net/http"

	"github.com/boson-chat/auth/config"
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
	mux.HandleFunc("GET /internal/email/default-mjml", manage(h.emailDefaultMJML))
}

// maxPreviewBody fits two custom HTML documents (layout_html, html) of
// config.MaxEmailFileBytes each, JSON-escaped, with the other fields.
const maxPreviewBody = 4*config.MaxEmailFileBytes + 64<<10

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
	// LayoutHTML and HTML: unsaved compiled MJML (a layout with
	// {{content}}, this template's whole email with {{link}}); "" = none.
	LayoutHTML *string `json:"layout_html"`
	HTML       *string `json:"html"`
}

// emailPreview: {template, subject?, body?, email?: {sender_name?, accent?,
// footer?, logo?}, layout_html?, html?} → {subject, html, text, from,
// warnings}, the email as it would be sent now with the unsaved values on
// top. Called while the admin types,
// so it is cheap (cached, rate-limited generously per admin).
func (h *Handlers) emailPreview(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req emailPreviewReq
	if err := decodeLimit(w, r, &req, maxPreviewBody); err != nil {
		writeError(w, r, err)
		return
	}
	p := principalFrom(r)
	if !h.Limits.allow(w, r, BucketEmailPreview, p.UserID) {
		return
	}
	in := email.PreviewInput{Template: req.Template, Subject: req.Subject, Body: req.Body, LayoutHTML: req.LayoutHTML, HTML: req.HTML}
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

type emailDefaultMJMLResp struct {
	MJML string `json:"mjml"`
}

// emailDefaultMJML: ?part=layout|verification|password_reset|account_setup|invite
// → {mjml}, Boson's default MJML source for the admin panel's MJML editor
// ("Reset to default"): the layout with {{content}}, or a whole email
// (that layout with the template's default text and {{link}} button).
func (h *Handlers) emailDefaultMJML(w nethttp.ResponseWriter, r *nethttp.Request) {
	src, err := email.DefaultMJML(r.URL.Query().Get("part"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, emailDefaultMJMLResp{MJML: src})
}
