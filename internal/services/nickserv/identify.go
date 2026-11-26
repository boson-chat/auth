package nickserv

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/boson-chat/auth/config"
)

// Patterns classify NickServ's replies to IDENTIFY (formatting stripped).
// A success or failure pattern may capture the canonical account name in
// a group named "account".
type Patterns struct {
	Success []*regexp.Regexp
	Failure []*regexp.Regexp
	// Refused: the services said no without saying the password is wrong
	// (suspended / frozen, too many sessions, ...).
	Refused []*regexp.Regexp
}

// DefaultPatterns are the replies of Anope 2.x and Atheme 7.x (English).
var DefaultPatterns = map[string]struct{ Success, Failure, Refused []string }{
	config.ServicesAnope: {
		Success: []string{`^Password accepted - you are now recognized\.`},
		Failure: []string{`^Password incorrect\.`, `^Nick \S+ isn't registered\.`},
		Refused: []string{
			`^Nick \S+ is currently suspended\.`,
			`has already reached the maximum number of simultaneous logins`,
			`^Access denied\.`,
		},
	},
	config.ServicesAtheme: {
		Success: []string{`^You are now (?:identified for|logged in as) (?P<account>[^\s.]\S*?)\.$`},
		Failure: []string{`^Invalid password for \S+\.`, `^\S+ is not a registered nickname\.`},
		Refused: []string{
			`because the account has been frozen`,
			`because the server configuration disallows it`,
			`^Password authentication is disabled`,
			`sessions logged in to`,
		},
	},
}

// PatternsFor returns the configured patterns, each list defaulting to the
// services package's.
func PatternsFor(cfg config.NickServConfig) (Patterns, error) {
	def := DefaultPatterns[cfg.ServicesPackage()]
	pick := func(env string, defaults []string) ([]*regexp.Regexp, error) {
		if strings.TrimSpace(env) != "" {
			return config.ParsePatterns(env)
		}
		out := make([]*regexp.Regexp, 0, len(defaults))
		for _, d := range defaults {
			out = append(out, regexp.MustCompile(d))
		}
		return out, nil
	}
	var p Patterns
	var err error
	if p.Success, err = pick(cfg.IdentifySuccess, def.Success); err != nil {
		return p, err
	}
	if p.Failure, err = pick(cfg.IdentifyFailure, def.Failure); err != nil {
		return p, err
	}
	if p.Refused, err = pick(cfg.IdentifyRefused, def.Refused); err != nil {
		return p, err
	}
	if len(p.Success) == 0 || len(p.Failure) == 0 {
		return p, fmt.Errorf("nickserv: IDENTIFY needs at least one success and one failure pattern")
	}
	return p, nil
}

func matchAny(list []*regexp.Regexp, text string) (bool, string) {
	for _, re := range list {
		m := re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		if i := re.SubexpIndex("account"); i > 0 && i < len(m) {
			return true, m[i]
		}
		return true, ""
	}
	return false, ""
}

// Identify verifies a password by registering a short-lived client and
// sending "IDENTIFY <account> <password>" to NickServ, the last resort for
// servers without SASL (ngircd). The answer is read from NickServ's
// notices with the Patterns; RPL_LOGGEDIN (900) also counts as success.
//
// Only a reply from ServiceNick counts. With ServicesServer set, the check
// first WHOISes ServiceNick and sends nothing unless it sits on that
// server, so an impostor holding the nick while services are down never
// sees a password.
type Identify struct {
	Dialer         IRCDialer
	ServiceNick    string
	Target         string
	ServicesServer string
	Patterns       Patterns
}

func (s *Identify) Verify(ctx context.Context, cr Credentials) (*Account, error) {
	c, err := s.Dialer.open(ctx)
	if err != nil {
		return nil, err
	}
	defer c.close()
	if err := c.hello(s.Dialer.ServerPassword, false); err != nil {
		return nil, err
	}
	// 1. Registration.
	for registered := false; !registered; {
		m, err := c.read()
		if err != nil {
			return nil, err
		}
		if err := fatalRegistration(m); err != nil {
			return nil, err
		}
		switch {
		case nickError(m.Command):
			if err := c.renick(); err != nil {
				return nil, err
			}
		case m.Command == "001":
			c.nick = m.Param(0)
			registered = true
		}
	}
	// 2. Is NickServ the real one?
	if s.ServicesServer != "" {
		if err := s.checkService(c); err != nil {
			return nil, err
		}
	}
	// 3. IDENTIFY.
	if err := c.send("PRIVMSG " + s.Target + " :IDENTIFY " + cr.Account + " " + cr.Password); err != nil {
		return nil, err
	}
	acct := &Account{Name: cr.Account}
	for {
		m, err := c.read()
		if err != nil {
			return nil, err
		}
		switch m.Command {
		case "900":
			if a := m.Param(2); a != "" && len(m.Params) >= 4 {
				acct.Name = a
			}
			return acct, nil
		case "401", "440": // no such nick / services down
			return nil, fmt.Errorf("%w: %s is not on the network", ErrUnavailable, s.ServiceNick)
		case "NOTICE", "PRIVMSG":
			if !strings.EqualFold(m.Nick(), s.ServiceNick) || !strings.EqualFold(m.Param(0), c.nick) {
				continue
			}
			text := StripFormatting(m.Last())
			if ok, name := matchAny(s.Patterns.Success, text); ok {
				if name != "" {
					acct.Name = name
				} else {
					s.awaitLoggedIn(ctx, c, acct)
				}
				return acct, nil
			}
			if ok, _ := matchAny(s.Patterns.Failure, text); ok {
				return nil, ErrInvalidCredentials
			}
			if ok, _ := matchAny(s.Patterns.Refused, text); ok {
				return nil, fmt.Errorf("%w: %s", ErrRefused, text)
			}
		}
	}
}

// awaitLoggedIn gives the server a moment to send RPL_LOGGEDIN with the
// services' spelling of the account name.
func (s *Identify) awaitLoggedIn(ctx context.Context, c *ircConn, acct *Account) {
	reset := shortTimeout(ctx, c.conn, 300*time.Millisecond)
	defer reset()
	for {
		m, err := c.read()
		if err != nil {
			return
		}
		if m.Command == "900" && len(m.Params) >= 4 {
			acct.Name = m.Param(2)
			return
		}
	}
}

// checkService WHOISes the service nick and requires it on ServicesServer.
func (s *Identify) checkService(c *ircConn) error {
	if err := c.send("WHOIS " + s.ServiceNick); err != nil {
		return err
	}
	onServer := false
	for {
		m, err := c.read()
		if err != nil {
			return err
		}
		switch m.Command {
		case "312": // RPL_WHOISSERVER <me> <nick> <server> :info
			onServer = strings.EqualFold(m.Param(1), s.ServiceNick) && strings.EqualFold(m.Param(2), s.ServicesServer)
		case "401":
			return fmt.Errorf("%w: %s is not on the network", ErrUnavailable, s.ServiceNick)
		case "318": // end of WHOIS
			if !onServer {
				return fmt.Errorf("%w: %s is not on %s; not sending the password", ErrUnavailable, s.ServiceNick, s.ServicesServer)
			}
			return nil
		}
	}
}
