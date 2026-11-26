package bridge

import (
	"regexp"
	"strings"
)

// The mapping below is the one the stack's bridge-sync used
// (boson-chat/stack images/bridgesync/sync.go), so the bridge accounts it
// made are the ones auth now keeps up to date, not duplicates.

// validName is evrd's account name rule (2-32 characters, a letter first).
var validName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{1,31}$`)

var identBad = regexp.MustCompile(`[^a-z0-9]`)

// Name is the bridge account name of a Boson username: the username in
// lower case. ok false: the bridge can't name it (the account is skipped).
func Name(username string) (name string, ok bool) {
	if !validName.MatchString(username) {
		return "", false
	}
	return strings.ToLower(username), true
}

// User is what auth knows of an account, as the bridge needs it.
type User struct {
	ID          string
	Username    string
	Email       string
	DisplayName string
	Disabled    bool
	// NickServAccount is the linked NickServ account ("" for local and
	// federated accounts).
	NickServAccount string
}

// Want is the bridge account for u, without its services login.
func Want(u User) Put {
	ident := identBad.ReplaceAllString(strings.ToLower(u.Username), "")
	if len(ident) > 10 {
		ident = ident[:10]
	}
	if ident == "" {
		ident = "boson"
	}
	nick := u.Username
	if u.NickServAccount != "" {
		nick = u.NickServAccount
	}
	real := strings.TrimSpace(u.DisplayName)
	if real == "" {
		real = u.Username
	}
	return Put{Subject: u.ID, Email: u.Email, Nick: nick, AltNick: nick + "_", Ident: ident, Realname: real, Disabled: u.Disabled}
}

// NoLogin is the services login of accounts auth has no password for
// (local and federated accounts): none. evrd checks the Boson token when
// a client connects either way.
var NoLogin = Auth{Method: "none"}

// clearsLogin reports whether a non-NickServ account's bridge login must
// be set to none: always for a new account, else only when the bridge holds
// a login (a password, or SASL / IDENTIFY). Accounts bridge-sync made have
// evrd's default (auto, no password); switching those to none would only
// reconnect everyone once for nothing.
func clearsLogin(cur *Account) bool {
	if cur == nil {
		return true
	}
	return cur.Auth.HasPassword || cur.Auth.Method == "sasl" || cur.Auth.Method == "nickserv"
}

// same reports whether cur already is w (the services login aside).
func same(cur *Account, w Put) bool {
	return cur != nil && cur.Subject == w.Subject && strings.EqualFold(cur.Email, w.Email) && cur.Nick == w.Nick &&
		cur.AltNick == w.AltNick && cur.Ident == w.Ident && cur.Realname == w.Realname && cur.Disabled == w.Disabled
}

// body is the PUT that makes cur into u's account; nil: nothing to change.
func body(u User, cur *Account) *Put {
	w := Want(u)
	login := u.NickServAccount == "" && clearsLogin(cur)
	if same(cur, w) && !login {
		return nil
	}
	if login {
		a := NoLogin
		w.Auth = &a
	}
	return &w
}
