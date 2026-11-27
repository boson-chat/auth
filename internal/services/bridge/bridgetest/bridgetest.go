// Package bridgetest is an in-memory evrd managed API (evrd docs/managed.md)
// for tests: accounts by name, fields left out of a PUT stay as they are,
// "" keeps the saved password and method none clears it, a subject held by
// another account is a 409, and Down makes every call fail.
// /api/managed/settings keeps the settings PUT (evrd 0.61); NoSettings
// makes it a 404, as an older evrd answers.
package bridgetest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Account is a stored account, with its saved password.
type Account struct {
	Username, Subject, Email, Nick, AltNick, Ident, Realname string
	Disabled                                                 bool
	Method, AuthAccount, Password                            string
}

// Call is one request the fake answered (or refused while down).
type Call struct {
	Method, Name string
	Body         string // raw request body
}

// Bridge is the fake managed API.
type Bridge struct {
	Token string
	// Down: every call gets a 503.
	Down atomic.Bool
	// NoSettings: /api/managed/settings is a 404 (an evrd before 0.61).
	NoSettings atomic.Bool

	mu       sync.Mutex
	accts    map[string]*Account
	calls    []Call
	settings map[string]any // set through PUT /api/managed/settings
	srv      *httptest.Server
}

var validName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{1,31}$`)

// New starts the fake (Close it, or use t.Cleanup(b.Close)).
func New(token string) *Bridge {
	b := &Bridge{Token: token, accts: map[string]*Account{}}
	b.srv = httptest.NewServer(b)
	return b
}

func (b *Bridge) URL() string { return b.srv.URL }
func (b *Bridge) Close()      { b.srv.Close() }

// Seed stores an account as if made earlier (e.g. by bridge-sync).
func (b *Bridge) Seed(a Account) {
	b.mu.Lock()
	defer b.mu.Unlock()
	a.Username = strings.ToLower(a.Username)
	if a.Method == "" {
		a.Method = "auto" // evrd's default
	}
	b.accts[a.Username] = &a
}

// Get returns a copy of the account (nil: none).
func (b *Bridge) Get(name string) *Account {
	b.mu.Lock()
	defer b.mu.Unlock()
	a, ok := b.accts[strings.ToLower(name)]
	if !ok {
		return nil
	}
	c := *a
	return &c
}

// Names lists the accounts' names, sorted.
func (b *Bridge) Names() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for n := range b.accts {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Setting returns a setting PUT through /api/managed/settings (nil: never set).
func (b *Bridge) Setting(name string) any {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.settings[name]
}

// Guests is the "guests" setting PUT through the settings API, if any.
func (b *Bridge) Guests() (on, set bool) {
	v, ok := b.Setting("guests").(bool)
	return v, ok
}

// Calls returns the requests so far and forgets them.
func (b *Bridge) Calls() []Call {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.calls
	b.calls = nil
	return c
}

func view(a *Account) map[string]any {
	return map[string]any{
		"username": a.Username, "subject": a.Subject, "email": a.Email, "nick": a.Nick, "altNick": a.AltNick,
		"ident": a.Ident, "realname": a.Realname, "disabled": a.Disabled,
		"auth": map[string]any{"method": a.Method, "account": a.AuthAccount, "hasPassword": a.Password != ""},
	}
}

func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	raw := string(data)
	name := strings.ToLower(strings.TrimPrefix(r.URL.Path, "/api/managed/users/"))
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, Call{Method: r.Method, Name: name, Body: raw})
	if b.Down.Load() {
		http.Error(w, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+b.Token {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/api/managed/users" && r.Method == http.MethodGet {
		var list []map[string]any
		for _, a := range b.accts {
			list = append(list, view(a))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"users": list})
		return
	}
	if r.URL.Path == "/api/managed/settings" && !b.NoSettings.Load() {
		b.serveSettings(w, r.Method, raw)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/managed/users/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a, ok := b.accts[name]
		if !ok {
			http.Error(w, `{"error":"no such account"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(view(a))
	case http.MethodDelete:
		if _, ok := b.accts[name]; !ok {
			http.Error(w, `{"error":"no such account"}`, http.StatusNotFound)
			return
		}
		delete(b.accts, name)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPut:
		b.put(w, name, raw)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (b *Bridge) put(w http.ResponseWriter, name, raw string) {
	if !validName.MatchString(name) {
		http.Error(w, `{"error":"invalid username"}`, http.StatusUnprocessableEntity)
		return
	}
	var in struct {
		Subject, Email, Nick, AltNick, Ident, Realname *string
		Disabled                                       *bool
		Auth                                           *struct{ Method, Account, Password string }
	}
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	if in.Subject != nil && *in.Subject != "" {
		for n, o := range b.accts {
			if o.Subject == *in.Subject && n != name {
				http.Error(w, `{"error":"subject taken"}`, http.StatusConflict)
				return
			}
		}
	}
	a, ok := b.accts[name]
	if !ok {
		a = &Account{Username: name, Nick: name, Ident: name, Method: "auto"}
	}
	set := func(dst *string, v *string) {
		if v != nil {
			*dst = *v
		}
	}
	set(&a.Subject, in.Subject)
	set(&a.Email, in.Email)
	set(&a.Nick, in.Nick)
	set(&a.AltNick, in.AltNick)
	set(&a.Ident, in.Ident)
	set(&a.Realname, in.Realname)
	if in.Disabled != nil {
		a.Disabled = *in.Disabled
	}
	if x := in.Auth; x != nil {
		switch x.Method {
		case "sasl", "nickserv", "auto", "none":
		default:
			http.Error(w, `{"error":"auth.method must be sasl, nickserv, auto or none"}`, http.StatusUnprocessableEntity)
			return
		}
		a.Method, a.AuthAccount = x.Method, x.Account
		switch {
		case x.Method == "none":
			a.Password = ""
		case x.Password != "":
			a.Password = x.Password
		}
	}
	if a.Realname == "" {
		a.Realname = a.Nick
	}
	b.accts[name] = a
	if !ok {
		w.WriteHeader(http.StatusCreated)
	}
	_ = json.NewEncoder(w).Encode(view(a))
}

// serveSettings is GET/PUT/DELETE /api/managed/settings, with evrd's
// defaults under what was set.
func (b *Bridge) serveSettings(w http.ResponseWriter, method, raw string) {
	switch method {
	case http.MethodGet:
	case http.MethodDelete:
		b.settings = nil
	case http.MethodPut:
		var in map[string]any
		if err := json.Unmarshal([]byte(raw), &in); err != nil {
			http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
			return
		}
		for k, v := range in {
			switch k {
			case "guests":
				if _, ok := v.(bool); !ok {
					http.Error(w, `{"error":"guests must be true or false"}`, http.StatusUnprocessableEntity)
					return
				}
			case "guestsMax", "guestsPerIP", "guestLingerSeconds", "nickGuardGraceSeconds":
				if n, ok := v.(float64); !ok || n < 0 {
					http.Error(w, `{"error":"`+k+` must be 0 or more"}`, http.StatusUnprocessableEntity)
					return
				}
			default:
				http.Error(w, `{"error":"unknown field `+k+`"}`, http.StatusUnprocessableEntity)
				return
			}
		}
		if b.settings == nil {
			b.settings = map[string]any{}
		}
		for k, v := range in {
			b.settings[k] = v
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	out := map[string]any{"guests": false, "guestsMax": 100, "guestsPerIP": 3, "guestLingerSeconds": 30, "nickGuardGraceSeconds": 60}
	set := []string{}
	for k, v := range b.settings {
		out[k] = v
		set = append(set, k)
	}
	sort.Strings(set)
	out["set"] = set
	_ = json.NewEncoder(w).Encode(out)
}
