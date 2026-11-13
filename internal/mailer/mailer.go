// Package mailer sends email: SMTP in production, a log-only mailer in dev.
package mailer

import (
	"context"
	"fmt"
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
}

type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// New returns the SMTP mailer, or the log mailer when SMTP_HOST is empty.
func New(cfg config.SMTPConfig) (Mailer, error) {
	if cfg.Host == "" {
		return LogMailer{}, nil
	}
	return NewSMTP(cfg)
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

// LogMailer writes the message (including its link) to the log. Dev only:
// the link is a live credential.
type LogMailer struct{}

func (LogMailer) Send(ctx context.Context, m Message) error {
	logger.FromCtx(ctx).Warn().Str("to", m.To).Str("subject", m.Subject).Str("link", m.Link).
		Msg("SMTP_HOST not set: email not sent, logging it instead")
	return nil
}
