// Package email sends the verification, password-reset and account-setup
// emails. Without auth.email in the stack config file they are Boson's
// built-in templates (templates/*); with it, every email is rendered from
// plain text (Boson's wording or the file's per-template subject / body
// with {{variables}}) into the branded layout (render.go).
//
// Links carry the token in the URL fragment (#token=...), which browsers
// never send to servers, so it stays out of access logs and Referer headers.
package email

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	htmltemplate "html/template"
	nethttp "net/http"
	netmail "net/mail"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	texttemplate "text/template"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/mailer"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/metrics"
)

//go:embed templates/*
var templates embed.FS

var (
	textTmpl = texttemplate.Must(texttemplate.ParseFS(templates, "templates/*.txt"))
	htmlTmpl = htmltemplate.Must(htmltemplate.ParseFS(templates, "templates/*.html"))
)

const (
	PurposeVerify = "verify_email"
	PurposeReset  = "reset_password"
	PurposeSetup  = "account_setup"
	PurposeInvite = "invite"
	PurposeTest   = "test"
	VerifyPath    = "/verify-email"
	ResetPath     = "/reset-password"
	sendTimeout   = 30 * time.Second
)

type EmailServiceImpl interface {
	// SendVerification and SendPasswordReset send in the background so the
	// response time does not depend on the mail server (or on whether an
	// account exists). Wait blocks until queued sends finish.
	SendVerification(ctx context.Context, u *user.User, token string, ttl time.Duration)
	SendPasswordReset(ctx context.Context, u *user.User, token string, ttl time.Duration)
	// SendAccountSetup invites a user an admin created to choose a password
	// (a reset-password token, opened on the same page).
	SendAccountSetup(ctx context.Context, u *user.User, token string, ttl time.Duration)
	// SetSiteName changes the product name in subjects and bodies.
	SetSiteName(name string)
	// SetConfig applies auth.email from the stack config file; nil means
	// Boson's built-in emails (byte for byte as without the file).
	SetConfig(c *config.EmailConfig)
	// Preview renders template with sample values for username (the admin
	// asking) and optional unsaved subject / body.
	Preview(ctx context.Context, template, username string, over *config.EmailTemplate) (Rendered, error)
	// SendTest sends template with sample values to `to`, waits for the
	// mail server's answer and audits it (email_test_sent) as actorID.
	SendTest(ctx context.Context, actorID, template, username, to string) (Rendered, error)
	// Logging reports whether emails are only logged (no SMTP_HOST).
	Logging() bool
	Wait()
}

type Options struct {
	AppURL   string // link base
	SiteName string
	// Logo returns the branding logo URL for emails (auth.email.logo).
	Logo func() string
	// TTLs of the links, for the sample values of previews and tests.
	VerifyTTL, ResetTTL, SetupTTL, InviteTTL time.Duration
	// Audit records test sends (nil: not audited).
	Audit audit.AuditServiceImpl
}

type EmailService struct {
	Mailer  mailer.Mailer
	Metrics *metrics.Metrics
	opts    Options
	// siteName is opts.SiteName, replaceable at runtime (SetSiteName).
	siteName atomic.Pointer[string]
	cfg      atomic.Pointer[config.EmailConfig]
	wg       sync.WaitGroup
}

func NewEmailService(m mailer.Mailer, met *metrics.Metrics, opts Options) EmailServiceImpl {
	if opts.Logo == nil {
		opts.Logo = func() string { return "" }
	}
	s := &EmailService{Mailer: m, Metrics: met, opts: opts}
	s.SetSiteName(opts.SiteName)
	return s
}

// SetSiteName changes the product name used in emails (network.name in
// the stack config file).
func (s *EmailService) SetSiteName(name string) { s.siteName.Store(&name) }

func (s *EmailService) SetConfig(c *config.EmailConfig) { s.cfg.Store(c) }

func (s *EmailService) site() string { return *s.siteName.Load() }

type data struct {
	SiteName  string
	Username  string
	Link      string
	ExpiresIn string
}

func (s *EmailService) link(path, token string) string {
	return s.opts.AppURL + path + "#token=" + url.QueryEscape(token)
}

func humanize(d time.Duration) string {
	plural := func(n time.Duration, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d >= 48*time.Hour && d%(24*time.Hour) == 0:
		return plural(d/(24*time.Hour), "day")
	case d >= time.Hour && d%time.Hour == 0:
		return plural(d/time.Hour, "hour")
	case d >= time.Minute && d%time.Minute == 0:
		return plural(d/time.Minute, "minute")
	default:
		return d.String()
	}
}

func (s *EmailService) SendVerification(ctx context.Context, u *user.User, token string, ttl time.Duration) {
	s.sendUser(ctx, u, catalog[config.EmailVerification], s.link(VerifyPath, token), ttl)
}

func (s *EmailService) SendPasswordReset(ctx context.Context, u *user.User, token string, ttl time.Duration) {
	s.sendUser(ctx, u, catalog[config.EmailPasswordReset], s.link(ResetPath, token), ttl)
}

func (s *EmailService) SendAccountSetup(ctx context.Context, u *user.User, token string, ttl time.Duration) {
	s.sendUser(ctx, u, catalog[config.EmailAccountSetup], s.link(ResetPath, token), ttl)
}

// render builds an email: Boson's built-in templates while auth.email is
// absent (and nothing is overridden), otherwise the branded layout.
func (s *EmailService) render(tpl template, v Vars, over *config.EmailTemplate) (Rendered, error) {
	cfg := s.cfg.Load()
	if cfg == nil && over == nil && tpl.legacy != "" {
		return legacy(tpl, v)
	}
	return branded(tpl, cfg, over, v, s.opts.Logo())
}

// legacy renders the embedded templates exactly as before branding existed.
func legacy(tpl template, v Vars) (Rendered, error) {
	d := data{SiteName: v.Network, Username: v.Username, Link: v.Link, ExpiresIn: v.Expires}
	var text, html bytes.Buffer
	if err := textTmpl.ExecuteTemplate(&text, tpl.legacy+".txt", d); err != nil {
		return Rendered{}, err
	}
	if err := htmlTmpl.ExecuteTemplate(&html, tpl.legacy+".html", d); err != nil {
		return Rendered{}, err
	}
	var subject string
	switch tpl.name {
	case config.EmailVerification:
		subject = "Verify your email for " + v.Network
	case config.EmailPasswordReset:
		subject = "Reset your " + v.Network + " password"
	case config.EmailAccountSetup:
		subject = "Your " + v.Network + " account"
	}
	return Rendered{Subject: subject, Text: text.String(), HTML: html.String()}, nil
}

func (s *EmailService) message(to string, r Rendered, link string) mailer.Message {
	msg := mailer.Message{To: to, Subject: r.Subject, Text: r.Text, HTML: r.HTML, Link: link}
	if cfg := s.cfg.Load(); cfg != nil {
		msg.FromName = cfg.SenderName
	}
	return msg
}

func (s *EmailService) sendUser(ctx context.Context, u *user.User, tpl template, link string, ttl time.Duration) {
	to := u.EmailOrEmpty() // only ever the stored address
	if to == "" {
		return
	}
	r, err := s.render(tpl, Vars{Network: s.site(), Username: u.Username, Link: link, Expires: humanize(ttl)}, nil)
	if err != nil {
		logger.FromCtx(ctx).Error().Err(err).Msg("email template")
		return
	}
	msg := s.message(to, r, link)
	purpose := tpl.purpose
	bg := context.WithoutCancel(ctx)
	s.wg.Go(func() {
		ctx, cancel := context.WithTimeout(bg, sendTimeout)
		defer cancel()
		if err := s.Mailer.Send(ctx, msg); err != nil {
			s.Metrics.EmailSent(ctx, purpose, metrics.OutcomeError)
			logger.FromCtx(ctx).Error().Err(err).Str("user_id", u.ID).Str("purpose", purpose).Msg("sending email failed")
			return
		}
		s.Metrics.EmailSent(ctx, purpose, metrics.OutcomeSuccess)
	})
}

// ErrUnknownTemplate: the template name is not one of config.EmailTemplates.
var ErrUnknownTemplate = apperr.Invalid("template must be one of " + strings.Join(config.EmailTemplates, ", "))

// sample returns the values used in previews and test emails: links carry
// a placeholder token that no page accepts.
func (s *EmailService) sample(name, username string) (template, Vars, error) {
	tpl, ok := catalog[name]
	if !ok {
		return template{}, Vars{}, ErrUnknownTemplate
	}
	v := Vars{Network: s.site(), Username: username, Inviter: username}
	switch name {
	case config.EmailVerification:
		v.Link, v.Expires = s.link(VerifyPath, "example-token"), humanize(s.opts.VerifyTTL)
	case config.EmailPasswordReset:
		v.Link, v.Expires = s.link(ResetPath, "example-token"), humanize(s.opts.ResetTTL)
	case config.EmailAccountSetup:
		v.Link, v.Expires = s.link(ResetPath, "example-token"), humanize(s.opts.SetupTTL)
	case config.EmailInvite:
		v.Link, v.Expires = s.opts.AppURL+"/#invite=inv_example", humanize(s.opts.InviteTTL)
	}
	return tpl, v, nil
}

func (s *EmailService) Preview(_ context.Context, name, username string, over *config.EmailTemplate) (Rendered, error) {
	tpl, v, err := s.sample(name, username)
	if err != nil {
		return Rendered{}, err
	}
	if over != nil {
		for field, p := range map[string]*string{"subject": over.Subject, "body": over.Body} {
			if p == nil {
				continue
			}
			check := config.CheckSubject
			if field == "body" {
				check = config.CheckBody
			}
			if msg := check(*p); msg != "" {
				return Rendered{}, apperr.Invalid(field + " " + msg)
			}
		}
		if over.Subject == nil && over.Body == nil {
			over = nil
		}
	}
	return s.render(tpl, v, over)
}

func (s *EmailService) SendTest(ctx context.Context, actorID, name, username, to string) (Rendered, error) {
	tpl, v, err := s.sample(name, username)
	if err != nil {
		return Rendered{}, err
	}
	if a, err := netmail.ParseAddress(to); err != nil || a.Address != to || len(to) > 254 {
		return Rendered{}, apperr.Invalid("to must be an email address such as admin@example.com")
	}
	r, err := s.render(tpl, v, nil)
	if err != nil {
		return Rendered{}, err
	}
	r.Subject = "[Test] " + r.Subject
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	record := func(outcome string) {
		if s.opts.Audit != nil {
			s.opts.Audit.Record(ctx, actorID, audit.EventEmailTestSent,
				map[string]any{"template": name, "to": to, "outcome": outcome, "logged_only": s.Logging()})
		}
	}
	if err := s.Mailer.Send(ctx, s.message(to, r, v.Link)); err != nil {
		s.Metrics.EmailSent(ctx, PurposeTest, metrics.OutcomeError)
		record(metrics.OutcomeError)
		logger.FromCtx(ctx).Warn().Err(err).Str("template", name).Msg("test email failed")
		return Rendered{}, apperr.New(nethttp.StatusBadGateway, "email_send_failed", "the mail server did not accept the email: "+err.Error())
	}
	s.Metrics.EmailSent(ctx, PurposeTest, metrics.OutcomeSuccess)
	record(metrics.OutcomeSuccess)
	return r, nil
}

func (s *EmailService) Logging() bool {
	m := s.Mailer
	if sw, ok := m.(*mailer.Swappable); ok {
		m = sw.Current()
	}
	_, ok := m.(mailer.LogMailer)
	return ok
}

func (s *EmailService) Wait() { s.wg.Wait() }
