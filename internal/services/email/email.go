// Package email sends the verification and password-reset emails.
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
	"net/url"
	"sync"
	"sync/atomic"
	texttemplate "text/template"
	"time"

	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/mailer"
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
	Wait()
}

type Options struct {
	AppURL   string // link base
	SiteName string
}

type EmailService struct {
	Mailer  mailer.Mailer
	Metrics *metrics.Metrics
	opts    Options
	// siteName is opts.SiteName, replaceable at runtime (SetSiteName).
	siteName atomic.Pointer[string]
	wg       sync.WaitGroup
}

func NewEmailService(m mailer.Mailer, met *metrics.Metrics, opts Options) EmailServiceImpl {
	s := &EmailService{Mailer: m, Metrics: met, opts: opts}
	s.SetSiteName(opts.SiteName)
	return s
}

// SetSiteName changes the product name used in emails (network.name in
// the stack config file).
func (s *EmailService) SetSiteName(name string) { s.siteName.Store(&name) }

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
	s.send(ctx, u, PurposeVerify, "Verify your email for "+s.site(), "verify", s.link(VerifyPath, token), ttl)
}

func (s *EmailService) SendPasswordReset(ctx context.Context, u *user.User, token string, ttl time.Duration) {
	s.send(ctx, u, PurposeReset, "Reset your "+s.site()+" password", "reset", s.link(ResetPath, token), ttl)
}

func (s *EmailService) SendAccountSetup(ctx context.Context, u *user.User, token string, ttl time.Duration) {
	s.send(ctx, u, PurposeSetup, "Your "+s.site()+" account", "setup", s.link(ResetPath, token), ttl)
}

func (s *EmailService) send(ctx context.Context, u *user.User, purpose, subject, tmpl, link string, ttl time.Duration) {
	to := u.EmailOrEmpty() // only ever the stored address
	if to == "" {
		return
	}
	d := data{SiteName: s.site(), Username: u.Username, Link: link, ExpiresIn: humanize(ttl)}
	var text, html bytes.Buffer
	if err := textTmpl.ExecuteTemplate(&text, tmpl+".txt", d); err != nil {
		logger.FromCtx(ctx).Error().Err(err).Msg("email template")
		return
	}
	if err := htmlTmpl.ExecuteTemplate(&html, tmpl+".html", d); err != nil {
		logger.FromCtx(ctx).Error().Err(err).Msg("email template")
		return
	}
	msg := mailer.Message{To: to, Subject: subject, Text: text.String(), HTML: html.String(), Link: link}
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

func (s *EmailService) Wait() { s.wg.Wait() }
