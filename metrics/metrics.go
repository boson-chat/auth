// Package metrics defines the auth service's OpenTelemetry instruments and
// the meter provider that exports them (Prometheus on the internal
// listener's /metrics, optional OTLP push).
package metrics

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// ScopeName is the instrumentation scope of every instrument.
const ScopeName = "github.com/boson-chat/auth"

// Outcome labels. Kept to a fixed set so label cardinality stays bounded.
const (
	OutcomeSuccess            = "success"
	OutcomeInvalidCredentials = "invalid_credentials"
	OutcomeDisabled           = "disabled"
	OutcomeUnverified         = "unverified"
	OutcomeInvalid            = "invalid"
	OutcomeExpired            = "expired"
	OutcomeReuse              = "reuse"
	OutcomeRejected           = "rejected"
	OutcomeError              = "error"
	// OutcomeTaken: a guest asked for a nick that belongs to an account.
	OutcomeTaken = "taken"
	// NickServ checks: the services refused, couldn't be reached, or the
	// attempt was stopped by a lockout / rate limit before reaching them.
	OutcomeSuspended   = "suspended"
	OutcomeRefused     = "refused"
	OutcomeUnavailable = "unavailable"
	OutcomeLocked      = "locked"
	OutcomeRateLimited = "rate_limited"
)

// Metrics holds the instruments. The zero value is not usable; use New or Noop.
type Metrics struct {
	loginAttempts  metric.Int64Counter
	registrations  metric.Int64Counter
	refreshes      metric.Int64Counter
	refreshReuse   metric.Int64Counter
	emailsSent     metric.Int64Counter
	rateLimitHits  metric.Int64Counter
	passwordResets metric.Int64Counter
	guestVoice     metric.Int64Counter
	nickservCheck  metric.Int64Counter
}

// New creates the instruments on mp.
func New(mp metric.MeterProvider) (*Metrics, error) {
	m := mp.Meter(ScopeName)
	var err error
	c := func(name, desc string) metric.Int64Counter {
		if err != nil {
			return nil
		}
		var ctr metric.Int64Counter
		ctr, err = m.Int64Counter(name, metric.WithDescription(desc), metric.WithUnit("{event}"))
		return ctr
	}
	out := &Metrics{
		loginAttempts:  c("auth.login.attempts", "Login attempts by method and outcome."),
		registrations:  c("auth.registrations", "Account registrations by outcome."),
		refreshes:      c("auth.token.refreshes", "Refresh-token exchanges by outcome."),
		refreshReuse:   c("auth.token.refresh_reuse", "Already-used refresh tokens presented (family revoked)."),
		emailsSent:     c("auth.emails.sent", "Emails sent by purpose and outcome."),
		rateLimitHits:  c("auth.rate_limit.hits", "Requests rejected by the rate limiter, by bucket."),
		passwordResets: c("auth.password.resets", "Password reset completions by outcome."),
		guestVoice:     c("auth.voice.guest_tokens", "Guest voice token requests by outcome."),
		nickservCheck:  c("auth.nickserv.checks", "NickServ password checks by strategy and outcome."),
	}
	if err != nil {
		return nil, fmt.Errorf("metrics: %w", err)
	}
	return out, nil
}

// Noop returns instruments that record nothing.
func Noop() *Metrics {
	m, _ := New(noop.NewMeterProvider())
	return m
}

func outcome(o string) metric.AddOption {
	return metric.WithAttributes(attribute.String("outcome", o))
}

func (m *Metrics) LoginAttempt(ctx context.Context, method, o string) {
	m.loginAttempts.Add(ctx, 1, metric.WithAttributes(attribute.String("method", method), attribute.String("outcome", o)))
}

func (m *Metrics) Registration(ctx context.Context, o string) {
	m.registrations.Add(ctx, 1, outcome(o))
}

func (m *Metrics) Refresh(ctx context.Context, o string) {
	m.refreshes.Add(ctx, 1, outcome(o))
	if o == OutcomeReuse {
		m.refreshReuse.Add(ctx, 1)
	}
}

func (m *Metrics) EmailSent(ctx context.Context, purpose, o string) {
	m.emailsSent.Add(ctx, 1, metric.WithAttributes(attribute.String("purpose", purpose), attribute.String("outcome", o)))
}

func (m *Metrics) RateLimited(ctx context.Context, bucket string) {
	m.rateLimitHits.Add(ctx, 1, metric.WithAttributes(attribute.String("bucket", bucket)))
}

func (m *Metrics) PasswordReset(ctx context.Context, o string) {
	m.passwordResets.Add(ctx, 1, outcome(o))
}

func (m *Metrics) GuestVoiceToken(ctx context.Context, o string) {
	m.guestVoice.Add(ctx, 1, outcome(o))
}

// NickServCheck counts one NickServ verification (strategy: anope_rpc, ...).
func (m *Metrics) NickServCheck(ctx context.Context, strategy, o string) {
	m.nickservCheck.Add(ctx, 1, metric.WithAttributes(attribute.String("strategy", strategy), attribute.String("outcome", o)))
}
