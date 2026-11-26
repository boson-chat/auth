package nickserv

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type rpcReq struct {
	Method string   `json:"method"`
	Params []string `json:"params"`
	ID     string   `json:"id"`
}

// fakeJSONRPC serves handle(method, params) → (result, errCode, errMsg).
func fakeJSONRPC(t *testing.T, token string, handle func(method string, params []string) (any, int, string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if token != "" && r.Header.Get("Authorization") != "Bearer "+base64.StdEncoding.EncodeToString([]byte(token)) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": "", "error": map[string]any{"code": -32601, "message": "No authorization for method"}})
			return
		}
		var req rpcReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad request: %v", err)
			return
		}
		res, code, msg := handle(req.Method, req.Params)
		out := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if code != 0 {
			out["error"] = map[string]any{"code": code, "message": msg}
		} else {
			out["result"] = res
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
}

func anopeHandler(method string, p []string) (any, int, string) {
	switch method {
	case "anope.checkCredentials":
		switch {
		case !strings.EqualFold(p[0], "alice") && !strings.EqualFold(p[0], "sus"):
			return nil, anopeErrInvalidAccount, "Invalid account"
		case p[1] != secret:
			return nil, anopeErrInvalidPassword, "Invalid password"
		case strings.EqualFold(p[0], "sus"):
			return nil, anopeErrSuspended, "Account suspended"
		}
		return map[string]any{"account": "Alice", "confirmed": false, "uniqueid": uint64(18446744073709551000)}, 0, ""
	case "anope.account":
		return map[string]any{"display": "Alice", "email": "alice@example.org", "uniqueid": uint64(18446744073709551000)}, 0, ""
	}
	return nil, -32601, "Method not found"
}

func TestAnopeRPC(t *testing.T) {
	srv := fakeJSONRPC(t, "tok", anopeHandler)
	defer srv.Close()
	a := &Anope{RPC: NewJSONRPC(srv.URL, "tok", nil, 5*time.Second)}
	ctx := ctxTimeout(t, 5*time.Second)
	acct, err := a.Verify(ctx, Credentials{Account: "alice", Password: secret})
	if err != nil {
		t.Fatal(err)
	}
	if acct.Name != "Alice" || acct.Email != "alice@example.org" || acct.ID != "18446744073709551000" || acct.Confirmed == nil || *acct.Confirmed {
		t.Fatalf("%+v", acct)
	}
	for _, c := range []struct {
		acct, pw string
		want     error
	}{{"alice", "nope", ErrInvalidCredentials}, {"bob", secret, ErrInvalidCredentials}, {"sus", secret, ErrSuspended}} {
		if _, err := a.Verify(ctx, Credentials{Account: c.acct, Password: c.pw}); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.acct, err, c.want)
		}
	}
	// A token without access is a configuration problem, not a wrong password.
	bad := &Anope{RPC: NewJSONRPC(srv.URL, "wrong", nil, 5*time.Second)}
	_, err = bad.Verify(ctx, Credentials{Account: "alice", Password: secret})
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "rpc_user") {
		t.Fatalf("got %v", err)
	}
	noSecret(t, err)
}

func TestAnopeWithoutAccountMethod(t *testing.T) {
	srv := fakeJSONRPC(t, "", func(m string, p []string) (any, int, string) {
		if m == "anope.checkCredentials" {
			return anopeHandler(m, p)
		}
		return nil, -32601, "No authorization for method: anope.account"
	})
	defer srv.Close()
	a := &Anope{RPC: NewJSONRPC(srv.URL, "", nil, 5*time.Second)}
	acct, err := a.Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: secret})
	if err != nil || acct.Email != "" || acct.Name != "Alice" {
		t.Fatalf("%+v %v", acct, err)
	}
}

func TestRPCTransportErrors(t *testing.T) {
	slow := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(time.Second)
	}))
	defer slow.Close()
	redirect := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, "http://example.invalid/steal", nethttp.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	broken := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(500)
	}))
	defer broken.Close()
	garbage := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = io.WriteString(w, "<html>not json</html>")
	}))
	defer garbage.Close()
	for name, url := range map[string]string{"slow": slow.URL, "redirect": redirect.URL, "500": broken.URL, "garbage": garbage.URL, "down": "http://127.0.0.1:1/jsonrpc"} {
		a := &Anope{RPC: NewJSONRPC(url, "t", nil, 200*time.Millisecond)}
		_, err := a.Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: secret})
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: %v, want ErrUnavailable", name, err)
		}
		noSecret(t, err)
	}
}

// fakeAtheme keeps accounts and cookies like Atheme's RPC.
type fakeAtheme struct {
	mu       sync.Mutex
	accounts map[string]*fakeAthemeAccount
	cookies  map[string]string // cookie → account
	n        int
}

type fakeAthemeAccount struct {
	name, password, email, key string
	waitAuth, frozen           bool
}

func newFakeAtheme() *fakeAtheme {
	return &fakeAtheme{
		accounts: map[string]*fakeAthemeAccount{"alice": {name: "Alice", password: secret, email: "alice@example.org"}},
		cookies:  map[string]string{},
	}
}

func (f *fakeAtheme) handle(method string, p []string) (any, int, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch method {
	case "atheme.login":
		a := f.accounts[strings.ToLower(p[0])]
		switch {
		case a == nil:
			return nil, athemeFaultNoSuchSource, "The account is not registered."
		case a.frozen:
			return nil, athemeFaultNoPrivs, "The account has been frozen."
		case a.password != p[1]:
			return nil, athemeFaultAuthFail, "The password is incorrect."
		}
		f.n++
		c := fmt.Sprintf("cookie%d", f.n)
		f.cookies[c] = strings.ToLower(p[0])
		return c, 0, ""
	case "atheme.logout":
		if _, ok := f.cookies[p[0]]; !ok {
			return nil, 15, "Invalid authcookie for this account."
		}
		delete(f.cookies, p[0])
		return "You are now logged out.", 0, ""
	case "atheme.command":
		cookie, svc, cmd, args := p[0], p[3], p[4], p[5:]
		if svc != "NickServ" {
			return nil, athemeFaultNoSuchSource, "Invalid service name."
		}
		switch cmd {
		case "INFO":
			a := f.accounts[strings.ToLower(args[0])]
			if f.cookies[cookie] != strings.ToLower(args[0]) {
				return nil, 15, "Invalid authcookie for this account."
			}
			lines := []string{"Information on \x02" + a.name + "\x02:", "Registered : Jan 01 2026", "Entity ID  : AAAAAAAAB", "Email      : " + a.email}
			if a.waitAuth {
				lines = append(lines, "\x02"+a.name+"\x02 has \x02NOT COMPLETED\x02 registration verification.")
			}
			return strings.Join(lines, "\n"), 0, ""
		case "REGISTER":
			if cookie != athemeNoCookie || p[1] != athemeNoAccount {
				return nil, athemeFaultAlreadyExists, "You are already logged in."
			}
			if _, ok := f.accounts[strings.ToLower(args[0])]; ok {
				return nil, athemeFaultAlreadyExists, "\x02" + args[0] + "\x02 is already registered."
			}
			if !strings.Contains(args[2], "@") {
				return nil, athemeFaultBadParams, "\x02" + args[2] + "\x02 is not a valid e-mail address."
			}
			f.accounts[strings.ToLower(args[0])] = &fakeAthemeAccount{name: args[0], password: args[1], email: args[2], key: "12345", waitAuth: true}
			return "An email containing nickname activation instructions has been sent to \x02" + args[2] + "\x02.\n" + args[0] + " is now registered to " + args[2] + ".", 0, ""
		case "VERIFY":
			a := f.accounts[strings.ToLower(args[1])]
			switch {
			case a == nil:
				return nil, athemeFaultNoSuchTarget, "\x02" + args[1] + "\x02 is not registered."
			case !a.waitAuth:
				return nil, athemeFaultNoChange, "not awaiting verification."
			case f.cookies[cookie] != strings.ToLower(args[1]):
				// Atheme 7.2: only the logged-in account may verify.
				return nil, athemeFaultBadParams, "Please log in before attempting to verify your registration."
			case false:
				return nil, athemeFaultNoChange, "not awaiting verification."
			case a.key != args[2]:
				return nil, athemeFaultBadParams, "Verification failed. Invalid key for \x02" + a.name + "\x02."
			}
			a.waitAuth = false
			return a.name + " has now been verified.", 0, ""
		}
	}
	return nil, athemeFaultNoSuchSource, "Invalid command"
}

// fakeXMLRPC serves the same handler over XML-RPC.
func fakeXMLRPC(t *testing.T, handle func(method string, params []string) (any, int, string)) *httptest.Server {
	return httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		var call struct {
			Method string   `xml:"methodName"`
			Params []string `xml:"params>param>value>string"`
		}
		if err := xml.NewDecoder(r.Body).Decode(&call); err != nil {
			t.Errorf("bad xml: %v", err)
			return
		}
		res, code, msg := handle(call.Method, call.Params)
		// Like Atheme's xmlrpc_normalizeBuffer: no control codes in XML.
		msg = strings.ReplaceAll(msg, "\x02", "")
		if s, ok := res.(string); ok {
			res = strings.ReplaceAll(s, "\x02", "")
		}
		var b strings.Builder
		b.WriteString(`<?xml version="1.0"?>` + "\n<methodResponse>")
		if code != 0 {
			fmt.Fprintf(&b, `<fault><value><struct><member><name>faultCode</name><value><int>%d</int></value></member><member><name>faultString</name><value><string>`, code)
			_ = xml.EscapeText(&b, []byte(msg))
			b.WriteString(`</string></value></member></struct></value></fault>`)
		} else {
			// Atheme sends untyped <value>text</value>.
			b.WriteString(`<params><param><value>`)
			_ = xml.EscapeText(&b, []byte(fmt.Sprint(res)))
			b.WriteString(`</value></param></params>`)
		}
		b.WriteString("</methodResponse>")
		_, _ = io.WriteString(w, b.String())
	}))
}

func TestAtheme(t *testing.T) {
	for _, transport := range []string{"jsonrpc", "xmlrpc"} {
		t.Run(transport, func(t *testing.T) {
			f := newFakeAtheme()
			var rpc Caller
			if transport == "jsonrpc" {
				srv := fakeJSONRPC(t, "", f.handle)
				defer srv.Close()
				rpc = NewJSONRPC(srv.URL, "", nil, 5*time.Second)
			} else {
				srv := fakeXMLRPC(t, f.handle)
				defer srv.Close()
				rpc = NewXMLRPC(srv.URL, nil, 5*time.Second)
			}
			a := &Atheme{RPC: rpc, KeepSession: true}
			ctx := ctxTimeout(t, 5*time.Second)

			acct, err := a.Verify(ctx, Credentials{Account: "alice", Password: secret, ClientIP: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			if acct.Name != "Alice" || acct.Email != "alice@example.org" || acct.ID != "AAAAAAAAB" || acct.Confirmed == nil || !*acct.Confirmed || acct.Session == nil {
				t.Fatalf("%+v", acct)
			}
			if err := a.EndSession(ctx, "alice", *acct.Session); err != nil {
				t.Fatal(err)
			}
			if len(f.cookies) != 0 {
				t.Fatal("logout didn't end the authcookie")
			}
			if _, err := a.Verify(ctx, Credentials{Account: "alice", Password: "x"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("wrong password: %v", err)
			}
			if _, err := a.Verify(ctx, Credentials{Account: "nobody", Password: "x"}); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("unknown: %v", err)
			}
			f.accounts["alice"].frozen = true
			if _, err := a.Verify(ctx, Credentials{Account: "alice", Password: secret}); !errors.Is(err, ErrSuspended) {
				t.Fatalf("frozen: %v", err)
			}

			// Sign-up with email verification.
			reg, err := a.Register(ctx, "Bob", secret, "bob@example.org", "")
			if err != nil || !reg.VerificationRequired || !strings.Contains(reg.Message, "activation") {
				t.Fatalf("register: %+v %v", reg, err)
			}
			if _, err := a.Register(ctx, "bob", secret, "bob@example.org", ""); !errors.Is(err, ErrAccountExists) {
				t.Fatalf("taken: %v", err)
			}
			var rej *RejectedError
			if _, err := a.Register(ctx, "carol", secret, "nope", ""); !errors.As(err, &rej) || !strings.Contains(rej.Message, "not a valid e-mail") || strings.Contains(rej.Message, "\x02") {
				t.Fatalf("bad email: %v", err)
			}
			acct, err = a.Verify(ctx, Credentials{Account: "bob", Password: secret})
			if err != nil || acct.Confirmed == nil || *acct.Confirmed {
				t.Fatalf("unverified login: %+v %v", acct, err)
			}
			if err := a.ConfirmRegistration(ctx, "bob", secret, "wrong", ""); !errors.Is(err, ErrInvalidCode) {
				t.Fatalf("wrong code: %v", err)
			}
			if err := a.ConfirmRegistration(ctx, "bob", "wrong-password", "12345", ""); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("wrong password: %v", err)
			}
			open := len(f.cookies)
			if err := a.ConfirmRegistration(ctx, "bob", secret, "12345", ""); err != nil {
				t.Fatal(err)
			}
			if len(f.cookies) != open {
				t.Fatal("ConfirmRegistration left a session open")
			}
			if err := a.ConfirmRegistration(ctx, "bob", "", "12345", ""); err != nil {
				t.Fatalf("confirming twice is fine: %v", err)
			}
			acct, err = a.Verify(ctx, Credentials{Account: "bob", Password: secret})
			if err != nil || !*acct.Confirmed {
				t.Fatalf("verified login: %+v %v", acct, err)
			}
		})
	}
}

func TestAthemeNoKeepSession(t *testing.T) {
	f := newFakeAtheme()
	srv := fakeJSONRPC(t, "", f.handle)
	defer srv.Close()
	a := &Atheme{RPC: NewJSONRPC(srv.URL, "", nil, 5*time.Second)}
	acct, err := a.Verify(ctxTimeout(t, 5*time.Second), Credentials{Account: "alice", Password: secret})
	if err != nil || acct.Session != nil || len(f.cookies) != 0 {
		t.Fatalf("session kept: %+v %v %v", acct, err, f.cookies)
	}
}
