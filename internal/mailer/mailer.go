// Package mailer sends email: SMTP in production, a log-only mailer in dev.
package mailer

import (
	"context"
	"errors"
	"fmt"
	netmail "net/mail"
	"strings"
	"sync/atomic"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/logger"
	mail "github.com/wneessen/go-mail"
)

// Message is one email with a plain-text and an HTML body.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
	// Link is the action link in the message; only the log mailer uses it.
	Link string
	// FromName replaces the display name of SMTP_FROM (auth.email.sender_name).
	FromName string
}

type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// ErrNotConfigured: no mail server is configured (SMTP_HOST is empty
// outside ENV=development), so nothing can be sent.
var ErrNotConfigured = errors.New("mailer: no mail server configured (SMTP_HOST is empty)")

// New returns the SMTP mailer. With SMTP_HOST empty it returns the log
// mailer in development (dev: ENV=development, the link is logged so it
// can be followed) and Disabled otherwise: production never claims to
// send, and never writes live links to the log.
func New(cfg config.SMTPConfig, dev bool) (Mailer, error) {
	if cfg.Host == "" {
		if dev {
			return LogMailer{From: cfg.From}, nil
		}
		return Disabled{From: cfg.From}, nil
	}
	return NewSMTP(cfg)
}

// Factory is New for one environment (dev: ENV=development).
func Factory(dev bool) func(config.SMTPConfig) (Mailer, error) {
	return func(cfg config.SMTPConfig) (Mailer, error) { return New(cfg, dev) }
}

// Disabled is the mailer without a mail server: every Send fails with
// ErrNotConfigured. Callers check Configured first and offer something
// else (no verification, a link for an admin to copy).
type Disabled struct {
	// From is SMTP_FROM (shown in previews; nothing is sent).
	From string
}

func (d Disabled) FromAddress() string { return d.From }

func (Disabled) Send(context.Context, Message) error { return ErrNotConfigured }

// Configured reports whether m can deliver email: false for Disabled
// (also behind a Swappable). The dev log mailer counts as configured: its
// "delivery" is the log.
func Configured(m Mailer) bool {
	if sw, ok := m.(*Swappable); ok {
		m = sw.Current()
	}
	switch m.(type) {
	case Disabled, *Disabled, nil:
		return false
	}
	return true
}

// SMTPMailer sends through an SMTP relay.
type SMTPMailer struct {
	cfg  config.SMTPConfig
	opts []mail.Option
}

func NewSMTP(cfg config.SMTPConfig) (*SMTPMailer, error) {
	opts := []mail.Option{mail.WithPort(cfg.Port), mail.WithTimeout(15 * time.Second)}
	switch cfg.TLS {
	case "tls":
		opts = append(opts, mail.WithSSL())
	case "none":
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	default:
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}
	if cfg.User != "" {
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(cfg.User), mail.WithPassword(cfg.Password))
	}
	// Validate options once at startup.
	if _, err := mail.NewClient(cfg.Host, opts...); err != nil {
		return nil, fmt.Errorf("mailer: %w", err)
	}
	return &SMTPMailer{cfg: cfg, opts: opts}, nil
}

func (s *SMTPMailer) Send(ctx context.Context, m Message) error {
	msg := mail.NewMsg()
	if err := msg.From(s.cfg.From); err != nil {
		return fmt.Errorf("mailer: from: %w", err)
	}
	if m.FromName != "" {
		addr, err := netmail.ParseAddress(s.cfg.From)
		if err != nil {
			return fmt.Errorf("mailer: from: %w", err)
		}
		if err := msg.FromFormat(m.FromName, addr.Address); err != nil {
			return fmt.Errorf("mailer: from: %w", err)
		}
	}
	if err := msg.To(m.To); err != nil {
		return fmt.Errorf("mailer: to: %w", err)
	}
	msg.Subject(m.Subject)
	msg.SetBodyString(mail.TypeTextPlain, m.Text)
	if m.HTML != "" {
		msg.AddAlternativeString(mail.TypeTextHTML, m.HTML)
	}
	c, err := mail.NewClient(s.cfg.Host, s.opts...)
	if err != nil {
		return err
	}
	return c.DialAndSendWithContext(ctx, msg)
}

// FromAddress is SMTP_FROM, the sender of every message.
func (s *SMTPMailer) FromAddress() string { return s.cfg.From }

// LogMailer writes the message (including its link) to the log. Dev only:
// the link is a live credential.
type LogMailer struct {
	// From is SMTP_FROM (shown in previews; nothing is sent).
	From string
}

func (l LogMailer) FromAddress() string { return l.From }

func (LogMailer) Send(ctx context.Context, m Message) error {
	logger.FromCtx(ctx).Warn().Str("to", m.To).Str("from_name", m.FromName).Str("subject", m.Subject).Str("link", m.Link).
		Msg("SMTP_HOST not set: email not sent, logging it instead")
	return nil
}

// Swappable forwards to a mailer that can be replaced at runtime (SMTP
// settings reloaded from the stack config file).
type Swappable struct {
	cur atomic.Pointer[Mailer]
}

// NewSwappable returns a Swappable starting with m.
func NewSwappable(m Mailer) *Swappable {
	s := &Swappable{}
	s.Set(m)
	return s
}

// Set replaces the mailer; sends already in flight finish on the old one.
func (s *Swappable) Set(m Mailer) { s.cur.Store(&m) }

// Current returns the mailer in use.
func (s *Swappable) Current() Mailer { return *s.cur.Load() }

func (s *Swappable) Send(ctx context.Context, m Message) error { return s.Current().Send(ctx, m) }

func (s *Swappable) FromAddress() string { return FromAddress(s.Current()) }

// FromAddress returns m's SMTP_FROM ("" when m doesn't say).
func FromAddress(m Mailer) string {
	if f, ok := m.(interface{ FromAddress() string }); ok {
		return f.FromAddress()
	}
	return ""
}

// FromHeader is the From: a message with display name name gets from a
// mailer sending as from (SMTP_FROM): name replaces from's display name.
func FromHeader(from, name string) string {
	if name == "" || from == "" {
		return from
	}
	addr, err := netmail.ParseAddress(from)
	if err != nil {
		return from
	}
	// Readable (not RFC 2047 encoded): this is for showing, not sending.
	q := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(name)
	return `"` + q + `" <` + addr.Address + `>`
}
