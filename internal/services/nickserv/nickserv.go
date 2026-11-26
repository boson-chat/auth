// Package nickserv verifies NickServ account passwords against an IRC
// network's services, with one of several strategies:
//
//   - anope_rpc: Anope 2.1's JSON-RPC (anope.checkCredentials, anope.account)
//   - atheme_jsonrpc / atheme_xmlrpc: Atheme's atheme.login (+ NickServ INFO,
//     REGISTER and VERIFY through atheme.command)
//   - sasl: SASL PLAIN on a short-lived IRC connection that never finishes
//     registering
//   - identify: /msg NickServ IDENTIFY on a short-lived IRC connection,
//     matching the services' reply notices (configurable patterns)
//
// Passwords are only ever written to the services connection: they are
// never logged, stored, or put into an error.
package nickserv

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/boson-chat/auth/config"
)

var (
	// ErrInvalidCredentials: no such account, or the wrong password.
	ErrInvalidCredentials = errors.New("nickserv: invalid account or password")
	// ErrSuspended: the services know the account but refuse it
	// (Anope suspended, Atheme frozen).
	ErrSuspended = errors.New("nickserv: account suspended")
	// ErrRefused: the services refused the login without saying the
	// password is wrong (too many sessions, ...). Not a failed guess.
	ErrRefused = errors.New("nickserv: login refused by services")
	// ErrUnavailable: the services or the IRC server couldn't be reached or
	// gave no usable answer in time.
	ErrUnavailable = errors.New("nickserv: services unavailable")
	// ErrUnsupported: the server can't do what the strategy needs (e.g. no
	// SASL PLAIN).
	ErrUnsupported = errors.New("nickserv: not supported by the server")
	// ErrAccountExists: registration of a name that is taken.
	ErrAccountExists = errors.New("nickserv: account already registered")
	// ErrInvalidCode: a wrong or expired registration verification code.
	ErrInvalidCode = errors.New("nickserv: invalid verification code")
)

// RejectedError is a registration the services refused, with their reason
// (formatting stripped). Show Message to the user.
type RejectedError struct{ Message string }

func (e *RejectedError) Error() string { return "nickserv: registration rejected: " + e.Message }

// Credentials is one login attempt.
type Credentials struct {
	Account  string
	Password string
	// ClientIP of the end user ("" = unknown), passed to services that log it.
	ClientIP string
}

// Session is an opaque services session (Atheme authcookie).
type Session struct {
	Token     string
	ExpiresAt time.Time
}

// Account is a verified NickServ account.
type Account struct {
	// Name is the services' spelling of the account name when they tell
	// us (Anope display, Atheme INFO, SASL 900), else what was typed.
	Name string
	// ID is the services' stable account id ("" = unknown): Anope's
	// uniqueid, Atheme's entity id. A different id under the same name
	// means the name was dropped and registered again.
	ID string
	// Email is "" when unknown (SASL / IDENTIFY never learn it).
	Email string
	// Confirmed is whether the services consider the registration (email)
	// confirmed; nil = unknown.
	Confirmed *bool
	// Session, when the services issue one (Atheme), else nil.
	Session *Session
}

// Registration is the result of registering an account.
type Registration struct {
	// VerificationRequired: the services emailed a code that must be
	// confirmed (ConfirmRegistration) before the account is complete.
	VerificationRequired bool
	// Message is the services' reply, formatting stripped.
	Message string
}

// Verifier checks a password.
type Verifier interface {
	Verify(ctx context.Context, c Credentials) (*Account, error)
}

// Registrar registers accounts (Atheme).
type Registrar interface {
	Register(ctx context.Context, account, password, email, clientIP string) (*Registration, error)
	ConfirmRegistration(ctx context.Context, account, code, clientIP string) error
}

// SessionEnder ends a services session (Atheme atheme.logout).
type SessionEnder interface {
	EndSession(ctx context.Context, account string, s Session) error
}

// Backend is the configured strategy.
type Backend struct {
	Strategy string
	Verifier Verifier
	// Registrar is nil when the strategy can't register.
	Registrar Registrar
	// Sessions is nil when the strategy has no services sessions.
	Sessions SessionEnder
}

// New builds the backend for cfg (already validated).
func New(cfg config.NickServConfig) (*Backend, error) {
	tlsConf, err := TLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	b := &Backend{Strategy: cfg.Strategy}
	switch cfg.Strategy {
	case config.StrategyAnopeRPC:
		b.Verifier = &Anope{RPC: NewJSONRPC(cfg.RPCURL, cfg.RPCToken, tlsConf, cfg.Timeout)}
	case config.StrategyAthemeJSONRPC, config.StrategyAthemeXMLRPC:
		var rpc Caller
		if cfg.Strategy == config.StrategyAthemeJSONRPC {
			rpc = NewJSONRPC(cfg.RPCURL, "", tlsConf, cfg.Timeout)
		} else {
			rpc = NewXMLRPC(cfg.RPCURL, tlsConf, cfg.Timeout)
		}
		a := &Atheme{RPC: rpc, KeepSession: cfg.StoreSession}
		b.Verifier, b.Sessions = a, a
		if cfg.Registration {
			b.Registrar = a
		}
	case config.StrategySASL, config.StrategyIdentify:
		dial := IRCDialer{
			Addr: cfg.IRCAddr, TLS: tlsConf, UseTLS: cfg.IRCTLS, ServerPassword: cfg.IRCPassword,
			NickPrefix: cfg.IRCNickPrefix,
		}
		if cfg.Strategy == config.StrategySASL {
			b.Verifier = &SASL{Dialer: dial}
			break
		}
		p, err := PatternsFor(cfg)
		if err != nil {
			return nil, err
		}
		b.Verifier = &Identify{Dialer: dial, ServiceNick: cfg.ServiceNick, Target: cfg.Target(),
			ServicesServer: cfg.ServicesServer, Patterns: p}
	default:
		return nil, fmt.Errorf("nickserv: unknown strategy %q", cfg.Strategy)
	}
	return b, nil
}

const (
	// MaxAccountLen bounds account names (services allow ~30-50).
	MaxAccountLen = 64
	// MaxPasswordLen bounds passwords (Anope's maxpasslen defaults to 50,
	// Atheme's PASSLEN is 288).
	MaxPasswordLen = 512
)

// ValidAccount reports whether name can be sent to the services as an
// account name: 1-64 bytes of printable UTF-8 without spaces, '@' (emails
// aren't account names), or a leading ':' / '#' / '&'.
func ValidAccount(name string) bool {
	if name == "" || len(name) > MaxAccountLen || !utf8.ValidString(name) {
		return false
	}
	if strings.ContainsAny(name[:1], ":#&") || strings.ContainsAny(name, " @*?!,") {
		return false
	}
	for _, r := range name {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

// ValidPassword reports whether pw can be sent: non-empty, bounded, and no
// CR, LF or NUL (which would end or split the IRC line or RPC parameter).
func ValidPassword(pw string) bool {
	return pw != "" && len(pw) <= MaxPasswordLen && !strings.ContainsAny(pw, "\r\n\x00")
}

// StripFormatting removes mIRC formatting codes (bold, colour, ...) from a
// services reply.
func StripFormatting(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case 0x02, 0x0f, 0x11, 0x16, 0x1d, 0x1e, 0x1f, 0x1a:
			continue
		case 0x03: // ^C[fg[,bg]]
			j := i + 1
			for n := 0; n < 2 && j < len(s) && s[j] >= '0' && s[j] <= '9'; n++ {
				j++
			}
			if j < len(s)-1 && s[j] == ',' && s[j+1] >= '0' && s[j+1] <= '9' {
				j++
				for n := 0; n < 2 && j < len(s) && s[j] >= '0' && s[j] <= '9'; n++ {
					j++
				}
			}
			i = j - 1
			continue
		case 0x04: // ^D[RRGGBB[,RRGGBB]]
			j := i + 1
			for n := 0; n < 6 && j < len(s) && isHex(s[j]); n++ {
				j++
			}
			i = j - 1
			continue
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// boolPtr returns &v.
func boolPtr(v bool) *bool { return &v }
