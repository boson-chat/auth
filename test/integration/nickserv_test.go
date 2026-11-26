package integration

import (
	"encoding/base64"
	"encoding/json"
	nethttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/services/account"
)

const nsPassword = "irc-secret-123"

// fakeServicesRPC is a JSON-RPC endpoint speaking enough Anope 2.1 /
// Atheme for the HTTP flows. Accounts: name → password.
type fakeServicesRPC struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls atomic.Int64
	down  atomic.Bool
	// Anope-ish account data.
	accounts  map[string]string
	ids       map[string]string
	emails    map[string]string
	confirmed map[string]bool
	// Atheme-ish state.
	cookies map[string]string
	keys    map[string]string
	logouts atomic.Int64
	n       int
}

func newFakeServicesRPC(t *testing.T, token string) *fakeServicesRPC {
	f := &fakeServicesRPC{
		accounts: map[string]string{}, ids: map[string]string{}, emails: map[string]string{},
		confirmed: map[string]bool{}, cookies: map[string]string{}, keys: map[string]string{},
	}
	f.srv = httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if f.down.Load() {
			w.WriteHeader(502)
			return
		}
		f.calls.Add(1)
		if token != "" && r.Header.Get("Authorization") != "Bearer "+base64.StdEncoding.EncodeToString([]byte(token)) {
			t.Errorf("missing/wrong bearer token")
		}
		var req struct {
			ID     string   `json:"id"`
			Method string   `json:"method"`
			Params []string `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		res, code, msg := f.handle(req.Method, req.Params)
		out := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if code != 0 {
			out["error"] = map[string]any{"code": code, "message": msg}
		} else {
			out["result"] = res
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServicesRPC) add(name, password, email string, confirmed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := strings.ToLower(name)
	f.accounts[k], f.emails[k], f.confirmed[k] = password, email, confirmed
	f.n++
	f.ids[k] = strconv.Itoa(1000 + f.n)
	f.ids[k+"\x00name"] = name
}

func (f *fakeServicesRPC) name(k string) string { return f.ids[k+"\x00name"] }

func (f *fakeServicesRPC) handle(method string, p []string) (any, int, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch method {
	case "anope.checkCredentials":
		k := strings.ToLower(p[0])
		pw, ok := f.accounts[k]
		if !ok {
			return nil, -32099, "Invalid account"
		}
		if pw != p[1] {
			return nil, -32098, "Invalid password"
		}
		id, _ := strconv.Atoi(f.ids[k])
		return map[string]any{"account": f.name(k), "confirmed": f.confirmed[k], "uniqueid": id}, 0, ""
	case "anope.account":
		k := strings.ToLower(p[0])
		return map[string]any{"display": f.name(k), "email": f.emails[k]}, 0, ""
	case "atheme.login":
		k := strings.ToLower(p[0])
		pw, ok := f.accounts[k]
		if !ok {
			return nil, 3, "The account is not registered."
		}
		if pw != p[1] {
			return nil, 5, "The password is incorrect."
		}
		f.n++
		c := "ck" + strconv.Itoa(f.n)
		f.cookies[c] = k
		return c, 0, ""
	case "atheme.logout":
		delete(f.cookies, p[0])
		f.logouts.Add(1)
		return "You are now logged out.", 0, ""
	case "atheme.command":
		switch p[4] {
		case "INFO":
			k := strings.ToLower(p[5])
			lines := []string{"Information on \x02" + f.name(k) + "\x02:", "Entity ID  : ID" + f.ids[k], "Email      : " + f.emails[k]}
			if !f.confirmed[k] {
				lines = append(lines, f.name(k)+" has \x02NOT COMPLETED\x02 registration verification.")
			}
			return strings.Join(lines, "\n"), 0, ""
		case "REGISTER":
			k := strings.ToLower(p[5])
			if _, ok := f.accounts[k]; ok {
				return nil, 8, p[5] + " is already registered."
			}
			f.accounts[k], f.emails[k], f.confirmed[k], f.keys[k] = p[6], p[7], false, "key-"+k
			f.n++
			f.ids[k], f.ids[k+"\x00name"] = strconv.Itoa(1000+f.n), p[5]
			return "An email containing nickname activation instructions has been sent to " + p[7] + ".", 0, ""
		case "VERIFY":
			k := strings.ToLower(p[6])
			if f.keys[k] != p[7] {
				return nil, 2, "Verification failed. Invalid key for " + p[6] + "."
			}
			f.confirmed[k] = true
			return p[6] + " has now been verified.", 0, ""
		}
	}
	return nil, -32601, "Method not found"
}

func nickServEnv(t *testing.T, strategy string, f *fakeServicesRPC, mutate ...func(*config.NickServConfig)) *env {
	return newEnv(t, func(c *config.Config) {
		c.AccountsConfig.Backend = config.AccountBackendNickServ
		c.NickServConfig = config.NickServConfig{
			Strategy: strategy, RPCURL: f.srv.URL, RPCToken: "anope-token",
			Timeout: 5 * time.Second, MaxConcurrent: 4, ServiceNick: "NickServ",
			Registration: true, LinkExisting: config.LinkExistingUnclaimed, StoreSession: true,
			RateAccountBurst: 1000, RateAccountPerMinute: 1000, RateIPBurst: 1000, RateIPPerMinute: 1000,
			LockoutThreshold: 3, LockoutIPThreshold: 100, LockoutWindow: 15 * time.Minute, LockoutDuration: 15 * time.Minute,
		}
		for _, m := range mutate {
			m(&c.NickServConfig)
		}
		if err := c.NickServConfig.Validate(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestNickServAnopeLoginFlow(t *testing.T) {
	f := newFakeServicesRPC(t, "anope-token")
	e := nickServEnv(t, config.StrategyAnopeRPC, f)
	f.add("Alice", nsPassword, "alice@example.org", true)

	// /v1/config tells clients where accounts live.
	r := e.api("GET", "/v1/config", nil)
	e.expect(r, 200, "")
	acc := r.body["accounts"].(map[string]any)
	if acc["backend"] != "nickserv" || acc["signup"] != false || acc["password_reset"] != false || !strings.Contains(acc["signup_message"].(string), "NickServ REGISTER") {
		t.Fatalf("accounts = %v", acc)
	}
	// Anope's RPC can't register: sign-up points at IRC.
	r = e.api("POST", "/v1/register", map[string]string{"username": "newbie", "email": "n@example.org", "password": nsPassword})
	e.expect(r, 403, "registration_unavailable")
	if !strings.Contains(r.str("message"), "/msg NickServ REGISTER") {
		t.Fatalf("message %q", r.str("message"))
	}

	// First sign-in creates the local record, keyed by the services' spelling.
	r = e.login("alice", nsPassword)
	e.expect(r, 200, "")
	at := r.str("access_token")
	if r.str("user", "username") != "Alice" || r.str("user", "email") != "alice@example.org" {
		t.Fatalf("user = %s", r.raw)
	}
	id := r.str("user", "id")
	me := e.api("GET", "/v1/me", nil, bearer(at))
	e.expect(me, 200, "")
	if me.body["user"].(map[string]any)["email_verified"] != true {
		t.Fatalf("confirmed Anope account → verified email: %s", me.raw)
	}
	e.expect(e.api("POST", "/v1/voice/token", map[string]any{}, bearer(at)), 200, "")
	sess := e.api("GET", "/v1/sessions", nil, bearer(at))
	if m := sess.list("sessions"); len(m) != 1 || m[0]["auth_method"] != "nickserv" {
		t.Fatalf("sessions = %s", sess.raw)
	}
	// Again: the same user.
	r = e.login("ALICE", nsPassword)
	e.expect(r, 200, "")
	if r.str("user", "id") != id {
		t.Fatal("second sign-in made a new user")
	}

	// Never stored: no password credential; the link row has no secret.
	db := e.sqlDB()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM password_credentials`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("password_credentials rows = %d (%v)", n, err)
	}
	var acct, servicesID, strategy string
	if err := db.QueryRow(`SELECT account, services_id, strategy FROM nickserv_accounts WHERE user_id = $1`, id).Scan(&acct, &servicesID, &strategy); err != nil {
		t.Fatal(err)
	}
	if acct != "Alice" || servicesID == "" || strategy != "anope_rpc" {
		t.Fatalf("link = %q %q %q", acct, servicesID, strategy)
	}
	var leaks int
	if err := db.QueryRow(`SELECT count(*) FROM audit_log WHERE meta::text LIKE '%' || $1 || '%'`, nsPassword).Scan(&leaks); err != nil || leaks != 0 {
		t.Fatalf("password in the audit log: %d %v", leaks, err)
	}

	// Passwords are NickServ's.
	e.expect(e.api("POST", "/v1/password/change", map[string]string{"current": nsPassword, "new": "another-password-1"}, bearer(at)), 409, "password_managed_by_nickserv")
	e.expect(e.api("POST", "/v1/password/forgot", map[string]string{"email": "alice@example.org"}), 409, "password_managed_by_nickserv")
	// Account names, not emails.
	e.expect(e.login("alice@example.org", nsPassword), 400, "invalid_request")

	// The IRC SASL bridge goes through NickServ too.
	v := e.internalAPI("POST", "/internal/v1/verify-password", map[string]string{"username": "alice", "password": nsPassword})
	if v.status != 200 || v.body["ok"] != true || v.str("user_id") != id {
		t.Fatalf("internal verify: %s", v.raw)
	}
	v = e.internalAPI("POST", "/internal/v1/verify-password", map[string]string{"username": "alice", "password": "nope"})
	if v.body["ok"] != false || v.str("reason") != "invalid_credentials" {
		t.Fatalf("internal verify wrong: %s", v.raw)
	}
}

func TestNickServLockout(t *testing.T) {
	f := newFakeServicesRPC(t, "anope-token")
	e := nickServEnv(t, config.StrategyAnopeRPC, f)
	f.add("bob", nsPassword, "", true)
	// One failure came from the internal check above in other tests; here:
	// threshold 3 → the 3rd failure locks.
	for i := 0; i < 2; i++ {
		e.expect(e.login("bob", "wrong"), 401, "invalid_credentials")
	}
	// A success resets the account's count.
	e.expect(e.login("bob", nsPassword), 200, "")
	for i := 0; i < 3; i++ {
		e.expect(e.login("bob", "wrong"), 401, "invalid_credentials")
	}
	before := f.calls.Load()
	r := e.login("bob", nsPassword)
	e.expect(r, 429, "account_locked")
	if ra, _ := strconv.Atoi(r.header.Get("Retry-After")); ra < 60 {
		t.Fatalf("Retry-After %q", r.header.Get("Retry-After"))
	}
	if f.calls.Load() != before {
		t.Fatal("a locked account still reached the services")
	}
	// Other accounts are unaffected.
	f.add("carl", nsPassword, "", true)
	e.expect(e.login("carl", nsPassword), 200, "")
	// Lockouts are shared state: they survive a restart (another replica).
	e.restart()
	e.expect(e.login("bob", nsPassword), 429, "account_locked")
	var failures int
	if err := e.sqlDB().QueryRow(`SELECT count(*) FROM nickserv_lockouts WHERE key = 'a:bob' AND locked_until > now()`).Scan(&failures); err != nil || failures != 1 {
		t.Fatalf("lockout row: %d %v", failures, err)
	}
}

func TestNickServLinking(t *testing.T) {
	f := newFakeServicesRPC(t, "anope-token")
	e := nickServEnv(t, config.StrategyAnopeRPC, f)

	// An admin pre-creates the Owner (no password): the NickServ sign-in adopts it.
	owner, err := e.app.Account.CreateUser(e.t.Context(), "", account.CreateUserInput{Username: "Carol", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	// A password can't be given in this backend.
	if _, err := e.app.Account.CreateUser(e.t.Context(), "", account.CreateUserInput{Username: "x", Password: "a-long-password-1"}); err == nil {
		t.Fatal("CreateUser with a password should be refused")
	}
	f.add("carol", nsPassword, "carol@example.org", true)
	r := e.login("carol", nsPassword)
	e.expect(r, 200, "")
	if r.str("user", "id") != owner.ID {
		t.Fatal("not linked to the pre-created account")
	}
	me := e.api("GET", "/v1/me", nil, bearer(r.str("access_token")))
	if !strings.Contains(string(me.raw), `"Owner"`) {
		t.Fatalf("roles lost: %s", me.raw)
	}

	// A local account someone can already sign in to is not taken over.
	db := e.sqlDB()
	dave, err := e.app.Account.CreateUser(e.t.Context(), "", account.CreateUserInput{Username: "dave"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO password_credentials (user_id, hash) VALUES ($1, 'x')`, dave.ID); err != nil {
		t.Fatal(err)
	}
	f.add("dave", nsPassword, "", true)
	e.expect(e.login("dave", nsPassword), 409, "account_name_conflict")

	// RFC 1459 folds [ and {, the services don't have to: [x] and {x} are
	// different NickServ accounts and must not share a local account.
	f.add("[x]", nsPassword, "", true)
	e.expect(e.login("[x]", nsPassword), 200, "")
	f.add("{x}", nsPassword, "", true)
	e.expect(e.login("{x}", nsPassword), 409, "account_name_conflict")

	// The name was dropped and registered again on IRC (new services id):
	// not the same person, so not the same Boson account.
	f.add("erin", nsPassword, "", true)
	e.expect(e.login("erin", nsPassword), 200, "")
	f.add("erin", "new-owner-pass", "", true)
	e.expect(e.login("erin", "new-owner-pass"), 409, "account_reregistered")

	// Unconfirmed at the services + require_email_verification.
	f.add("fred", nsPassword, "fred@example.org", false)
	e.expect(e.login("fred", nsPassword), 403, "email_not_verified")

	// A disabled local account stays disabled.
	r = e.login("[x]", nsPassword)
	if _, err := db.Exec(`UPDATE users SET disabled_at = now() WHERE username = '[x]'`); err != nil {
		t.Fatal(err)
	}
	e.expect(e.login("[x]", nsPassword), 403, "account_disabled")

	// Services down: 503, and it doesn't count as a failed guess.
	f.down.Store(true)
	for i := 0; i < 4; i++ {
		e.expect(e.login("carol", nsPassword), 503, "accounts_unavailable")
	}
	f.down.Store(false)
	e.expect(e.login("carol", nsPassword), 200, "")
}

func TestNickServAthemeSignupFlow(t *testing.T) {
	f := newFakeServicesRPC(t, "")
	e := nickServEnv(t, config.StrategyAthemeJSONRPC, f)

	r := e.api("GET", "/v1/config", nil)
	if acc := r.body["accounts"].(map[string]any); acc["signup"] != true || acc["signup_message"] != nil {
		t.Fatalf("accounts = %v", acc)
	}
	r = e.api("POST", "/v1/register", map[string]string{"username": "Gina", "email": "gina@example.org", "password": nsPassword})
	e.expect(r, 201, "")
	if r.str("verification") != "nickserv_code" || r.body["email_verification_required"] != true || !strings.Contains(r.str("message"), "activation") {
		t.Fatalf("register = %s", r.raw)
	}
	e.mail.none(t, 200*time.Millisecond) // the services send the email, not Boson
	e.expect(e.api("POST", "/v1/register", map[string]string{"username": "gina", "email": "g2@example.org", "password": nsPassword}), 409, "username_taken")

	// Not confirmed yet.
	e.expect(e.login("gina", nsPassword), 403, "email_not_verified")
	e.expect(e.api("POST", "/v1/register/confirm", map[string]string{"username": "gina", "password": nsPassword, "code": "wrong"}), 400, "invalid_code")
	e.expect(e.api("POST", "/v1/register/confirm", map[string]string{"username": "gina", "password": nsPassword, "code": "key-gina"}), 200, "")

	r = e.login("gina", nsPassword)
	e.expect(r, 200, "")
	id := r.str("user", "id")
	// The authcookie is kept sealed, never in clear.
	var enc []byte
	if err := e.sqlDB().QueryRow(`SELECT session_enc FROM nickserv_accounts WHERE user_id = $1`, id).Scan(&enc); err != nil || len(enc) == 0 {
		t.Fatalf("session_enc: %v %d", err, len(enc))
	}
	if strings.Contains(string(enc), "ck") {
		t.Fatal("authcookie stored in clear")
	}
	// Logout ends the services session too (the confirmations above logged
	// in and out of Atheme twice).
	before := f.logouts.Load()
	e.expect(e.api("POST", "/v1/logout", nil, bearer(r.str("access_token"))), 204, "")
	if f.logouts.Load() != before+1 {
		t.Fatalf("atheme.logout calls = %d", f.logouts.Load())
	}
	if err := e.sqlDB().QueryRow(`SELECT session_enc FROM nickserv_accounts WHERE user_id = $1`, id).Scan(&enc); err != nil || enc != nil {
		t.Fatalf("session not cleared: %v", err)
	}
	// Registration closed applies to NickServ sign-up too.
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"registration": "closed"}, bearer(e.nickServOwner(f))), 200, "")
	e.expect(e.api("POST", "/v1/register", map[string]string{"username": "hank", "email": "h@example.org", "password": nsPassword}), 403, "registration_closed")
}

// nickServOwner makes an Owner that signs in with NickServ.
func (e *env) nickServOwner(f *fakeServicesRPC) string {
	e.t.Helper()
	if _, err := e.app.Account.CreateUser(e.t.Context(), "", account.CreateUserInput{Username: "boss", Role: "owner"}); err != nil {
		e.t.Fatal(err)
	}
	f.add("boss", nsPassword, "boss@example.org", true)
	r := e.login("boss", nsPassword)
	e.expect(r, 200, "")
	return r.str("access_token")
}
