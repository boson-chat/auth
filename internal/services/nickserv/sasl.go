package nickserv

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// SASL verifies a password with SASL PLAIN on a connection that never
// finishes registering (no CAP END): the server holds the client in
// registration, relays AUTHENTICATE to the services, and answers 903
// (success) or 904 (failure). The connection then quits without ever
// becoming a user on the network.
type SASL struct {
	Dialer IRCDialer
}

func saslPayload(account, password string) string {
	// authzid empty, authcid = account (RFC 4616).
	return base64.StdEncoding.EncodeToString([]byte("\x00" + account + "\x00" + password))
}

func (s *SASL) Verify(ctx context.Context, cr Credentials) (*Account, error) {
	c, err := s.Dialer.open(ctx)
	if err != nil {
		return nil, err
	}
	defer c.close()
	if err := c.hello(s.Dialer.ServerPassword, true); err != nil {
		return nil, err
	}
	var caps []string
	acct := &Account{Name: cr.Account}
	for {
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
		case m.Command == "001", m.Command == "421" && strings.EqualFold(m.Param(1), "CAP"):
			// Registered without CAP negotiation: the server has no IRCv3.
			return nil, fmt.Errorf("%w: the IRC server does not support CAP/SASL", ErrUnsupported)
		case m.Command == "CAP":
			switch strings.ToUpper(m.Param(1)) {
			case "LS":
				caps = append(caps, strings.Fields(m.Last())...)
				if m.Param(2) == "*" && len(m.Params) > 3 {
					continue // more LS lines follow
				}
				if !saslPlainOffered(caps) {
					return nil, fmt.Errorf("%w: the IRC server does not offer SASL PLAIN (are the services linked?)", ErrUnsupported)
				}
				if err := c.send("CAP REQ :sasl"); err != nil {
					return nil, err
				}
			case "ACK":
				if err := c.send("AUTHENTICATE PLAIN"); err != nil {
					return nil, err
				}
			case "NAK":
				return nil, fmt.Errorf("%w: the IRC server refused the sasl capability", ErrUnsupported)
			}
		case m.Command == "AUTHENTICATE" && m.Param(0) == "+":
			if err := sendAuthenticate(c, saslPayload(cr.Account, cr.Password)); err != nil {
				return nil, err
			}
		case m.Command == "900": // RPL_LOGGEDIN <nick> <mask> <account> :...
			if a := m.Param(2); a != "" && len(m.Params) >= 4 {
				acct.Name = a
			}
		case m.Command == "903": // RPL_SASLSUCCESS
			if acct.Name == cr.Account {
				// 900 normally comes first; give a late one a moment.
				reset := shortTimeout(ctx, c.conn, 300*time.Millisecond)
				if m, err := c.read(); err == nil && m.Command == "900" && len(m.Params) >= 4 {
					acct.Name = m.Param(2)
				}
				reset()
			}
			return acct, nil
		case m.Command == "904": // ERR_SASLFAIL
			return nil, ErrInvalidCredentials
		case m.Command == "902": // ERR_NICKLOCKED: the account is locked/suspended
			return nil, ErrSuspended
		case m.Command == "905": // ERR_SASLTOOLONG
			return nil, fmt.Errorf("%w: SASL payload too long", ErrUnsupported)
		case m.Command == "906", m.Command == "907": // aborted / already authenticated
			return nil, fmt.Errorf("%w: SASL %s", ErrUnavailable, m.Command)
		}
	}
}

// saslPlainOffered reports whether the caps include sasl with PLAIN (or
// sasl without a mechanism list, as in CAP 301).
func saslPlainOffered(caps []string) bool {
	for _, c := range caps {
		name, val, hasVal := strings.Cut(c, "=")
		if !strings.EqualFold(name, "sasl") {
			continue
		}
		if !hasVal || val == "" {
			return true
		}
		for _, mech := range strings.Split(val, ",") {
			if strings.EqualFold(mech, "PLAIN") {
				return true
			}
		}
		return false
	}
	return false
}

// sendAuthenticate sends a SASL response in 400-byte chunks ("+" after an
// exact multiple of 400).
func sendAuthenticate(c *ircConn, payload string) error {
	for len(payload) >= 400 {
		if err := c.send("AUTHENTICATE " + payload[:400]); err != nil {
			return err
		}
		payload = payload[400:]
	}
	if payload == "" {
		payload = "+"
	}
	return c.send("AUTHENTICATE " + payload)
}
