package nickserv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Anope 2.1 rpc_user error codes (RPC::ERR_CUSTOM_START = -32099).
const (
	anopeErrInvalidAccount  = -32099
	anopeErrInvalidPassword = -32098
	anopeErrSuspended       = -32097
	jsonRPCMethodNotFound   = -32601
)

// Anope verifies passwords with Anope 2.1's JSON-RPC:
//
//   - anope.checkCredentials(account, password) (module rpc_user) →
//     {account, confirmed, uniqueid}; errors -32099 no such account,
//     -32098 wrong password, -32097 suspended;
//   - anope.account(account) (module rpc_data) → {display, email, ...},
//     for the email. Optional: a token without it just leaves Email empty.
//
// Anope 2.1's RPC can't register accounts: NickServ REGISTER through
// anope.command registers the calling nick ("RPC"), not a chosen name.
type Anope struct {
	RPC Caller
}

type anopeCredentials struct {
	Account   string      `json:"account"`
	Confirmed *bool       `json:"confirmed"`
	UniqueID  json.Number `json:"uniqueid"`
}

type anopeAccount struct {
	Display  string      `json:"display"`
	Email    *string     `json:"email"`
	UniqueID json.Number `json:"uniqueid"`
}

func (a *Anope) Verify(ctx context.Context, c Credentials) (*Account, error) {
	raw, err := a.RPC.Call(ctx, "anope.checkCredentials", c.Account, c.Password)
	if err != nil {
		var re *RPCError
		if errors.As(err, &re) {
			switch re.Code {
			case anopeErrInvalidAccount, anopeErrInvalidPassword:
				return nil, ErrInvalidCredentials
			case anopeErrSuspended:
				return nil, ErrSuspended
			case jsonRPCMethodNotFound:
				return nil, fmt.Errorf("%w: anope.checkCredentials is not available (load rpc_user and allow the method for the token): %s", ErrUnavailable, re.Message)
			}
			return nil, fmt.Errorf("%w: anope.checkCredentials: %s", ErrUnavailable, re.Message)
		}
		return nil, err
	}
	var cr anopeCredentials
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&cr); err != nil || cr.Account == "" {
		return nil, fmt.Errorf("%w: unexpected anope.checkCredentials result", ErrUnavailable)
	}
	acct := &Account{Name: cr.Account, ID: cr.UniqueID.String(), Confirmed: cr.Confirmed}
	// The email (and the id, for older 2.1 releases) from anope.account.
	if raw, err := a.RPC.Call(ctx, "anope.account", cr.Account); err == nil {
		var info anopeAccount
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		if dec.Decode(&info) == nil {
			if info.Email != nil {
				acct.Email = *info.Email
			}
			if acct.ID == "" {
				acct.ID = info.UniqueID.String()
			}
		}
	}
	return acct, nil
}
