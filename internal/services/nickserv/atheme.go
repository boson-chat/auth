package nickserv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Atheme fault codes (include/atheme/sourceinfo.h, enum cmd_faultcode).
const (
	athemeFaultNeedMoreParams = 1
	athemeFaultBadParams      = 2
	athemeFaultNoSuchSource   = 3
	athemeFaultNoSuchTarget   = 4
	athemeFaultAuthFail       = 5
	athemeFaultNoPrivs        = 6
	athemeFaultAlreadyExists  = 8
	athemeFaultTooMany        = 9
	athemeFaultEmailFail      = 10
	athemeFaultNoChange       = 12
	athemeFaultInternalError  = 16
)

// athemeCookieTTL: Atheme authcookies last an hour (authcookie.c); stored
// sessions are treated as expired a little earlier.
const athemeCookieTTL = 55 * time.Minute

// athemeNoCookie / athemeNoAccount stand in for "not logged in" in
// atheme.command: Atheme rejects empty parameters, and treats a cookie of
// length <= 1 as anonymous.
const (
	athemeNoCookie  = "."
	athemeNoAccount = "."
)

// Atheme verifies and registers accounts through Atheme's JSON-RPC or
// XML-RPC (misc/httpd + transport/jsonrpc or transport/xmlrpc):
//
//   - atheme.login(account, password, ip) → authcookie; faults 3 (not
//     registered), 5 (wrong password), 6 (frozen);
//   - atheme.command(cookie, account, ip, "NickServ", "INFO", account) for
//     the canonical name, entity id, email and verification state;
//   - atheme.command(".", ".", ip, "NickServ", "REGISTER", account, password, email)
//     and "VERIFY", "REGISTER", account, key for sign-up;
//   - atheme.logout(cookie, account).
type Atheme struct {
	RPC Caller
	// KeepSession returns the authcookie as the Account's Session; false
	// logs out right after the check.
	KeepSession bool
	// Now is for tests.
	Now func() time.Time
}

func (a *Atheme) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func sourceIP(ip string) string {
	if ip == "" || strings.ContainsAny(ip, " \r\n") {
		return "0.0.0.0"
	}
	return ip
}

func rpcString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%w: unexpected Atheme RPC result", ErrUnavailable)
	}
	return s, nil
}

func (a *Atheme) Verify(ctx context.Context, c Credentials) (*Account, error) {
	ip := sourceIP(c.ClientIP)
	raw, err := a.RPC.Call(ctx, "atheme.login", c.Account, c.Password, ip)
	if err != nil {
		var re *RPCError
		if errors.As(err, &re) {
			switch re.Code {
			case athemeFaultNoSuchSource, athemeFaultAuthFail:
				return nil, ErrInvalidCredentials
			case athemeFaultNoPrivs:
				return nil, ErrSuspended
			}
			return nil, fmt.Errorf("%w: atheme.login: %s", ErrUnavailable, re.Message)
		}
		return nil, err
	}
	cookie, err := rpcString(raw)
	if err != nil || cookie == "" {
		return nil, fmt.Errorf("%w: atheme.login returned no authcookie", ErrUnavailable)
	}
	acct := &Account{Name: c.Account}
	// INFO as the account itself shows its own (even hidden) email.
	if raw, err := a.RPC.Call(ctx, "atheme.command", cookie, c.Account, ip, "NickServ", "INFO", c.Account); err == nil {
		if text, err := rpcString(raw); err == nil {
			parseAthemeInfo(text, acct)
		}
	}
	if a.KeepSession {
		acct.Session = &Session{Token: cookie, ExpiresAt: a.now().Add(athemeCookieTTL)}
	} else {
		_, _ = a.RPC.Call(ctx, "atheme.logout", cookie, c.Account)
	}
	return acct, nil
}

var (
	athemeInfoHeader  = regexp.MustCompile(`^Information on (\S+?)(?: \(account (\S+?)\))?:$`)
	athemeInfoEmail   = regexp.MustCompile(`^Email\s*:\s*(\S+)`)
	athemeInfoID      = regexp.MustCompile(`^Entity ID\s*:\s*(\S+)`)
	athemeUnverified  = regexp.MustCompile(`has NOT COMPLETED registration verification`)
	athemeNeedsVerify = regexp.MustCompile(`(?i)activation instructions|verify|verification`)
)

// parseAthemeInfo reads NickServ INFO's reply lines into acct.
func parseAthemeInfo(text string, acct *Account) {
	confirmed := true
	for _, line := range strings.Split(text, "\n") {
		line = StripFormatting(line)
		if m := athemeInfoHeader.FindStringSubmatch(line); m != nil {
			if m[2] != "" {
				acct.Name = m[2]
			} else {
				acct.Name = m[1]
			}
		} else if m := athemeInfoEmail.FindStringSubmatch(line); m != nil {
			acct.Email = m[1]
		} else if m := athemeInfoID.FindStringSubmatch(line); m != nil {
			acct.ID = m[1]
		} else if athemeUnverified.MatchString(line) {
			confirmed = false
		}
	}
	acct.Confirmed = boolPtr(confirmed)
}

func (a *Atheme) EndSession(ctx context.Context, account string, s Session) error {
	if s.Token == "" {
		return nil
	}
	_, err := a.RPC.Call(ctx, "atheme.logout", s.Token, account)
	var re *RPCError
	if errors.As(err, &re) {
		return nil // already expired or invalid: nothing to end
	}
	return err
}

func (a *Atheme) Register(ctx context.Context, account, password, email, clientIP string) (*Registration, error) {
	raw, err := a.RPC.Call(ctx, "atheme.command", athemeNoCookie, athemeNoAccount, sourceIP(clientIP),
		"NickServ", "REGISTER", account, password, email)
	if err != nil {
		var re *RPCError
		if errors.As(err, &re) {
			msg := StripFormatting(re.Message)
			switch re.Code {
			case athemeFaultAlreadyExists:
				return nil, ErrAccountExists
			case athemeFaultNeedMoreParams, athemeFaultBadParams, athemeFaultNoPrivs, athemeFaultTooMany, athemeFaultEmailFail, athemeFaultAuthFail:
				return nil, &RejectedError{Message: msg}
			}
			return nil, fmt.Errorf("%w: NickServ REGISTER: %s", ErrUnavailable, msg)
		}
		return nil, err
	}
	text, err := rpcString(raw)
	if err != nil {
		return nil, err
	}
	text = StripFormatting(strings.ReplaceAll(text, "\n", " "))
	return &Registration{VerificationRequired: athemeNeedsVerify.MatchString(text), Message: text}, nil
}

func (a *Atheme) ConfirmRegistration(ctx context.Context, account, code, clientIP string) error {
	_, err := a.RPC.Call(ctx, "atheme.command", athemeNoCookie, athemeNoAccount, sourceIP(clientIP),
		"NickServ", "VERIFY", "REGISTER", account, code)
	if err == nil {
		return nil
	}
	var re *RPCError
	if errors.As(err, &re) {
		switch re.Code {
		case athemeFaultNoChange:
			return nil // not awaiting verification: already done
		case athemeFaultBadParams, athemeFaultNoSuchTarget, athemeFaultAuthFail, athemeFaultNeedMoreParams:
			return ErrInvalidCode
		case athemeFaultInternalError:
		default:
			return &RejectedError{Message: StripFormatting(re.Message)}
		}
		return fmt.Errorf("%w: NickServ VERIFY: %s", ErrUnavailable, StripFormatting(re.Message))
	}
	return err
}
