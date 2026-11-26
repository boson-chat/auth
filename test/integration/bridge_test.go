package integration

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	authhttp "github.com/boson-chat/auth/http"
	"github.com/boson-chat/auth/internal/services/bridge/bridgetest"
	"github.com/rs/zerolog"
)

// lockedBuffer collects the bridge service's logs.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func bridgeConfig(fb *bridgetest.Bridge) func(*config.Config) {
	return func(c *config.Config) {
		c.BridgeConfig = config.BridgeConfig{APIURL: fb.URL(), Token: fb.Token, PollInterval: 20 * time.Millisecond,
			RetryMin: 50 * time.Millisecond, RetryMax: 200 * time.Millisecond, Timeout: 2 * time.Second}
	}
}

// bridgeEnv is an env provisioning fb; run starts the outbox worker (and
// its startup full sync).
func bridgeEnv(t *testing.T, fb *bridgetest.Bridge, mutate ...func(*config.Config)) (*env, *lockedBuffer) {
	t.Helper()
	logs := &lockedBuffer{}
	l := zerolog.New(logs).Level(zerolog.DebugLevel)
	e := newEnvOpts(t, authhttp.Options{BridgeLog: &l, BridgeCredentialRetries: []time.Duration{50 * time.Millisecond, 100 * time.Millisecond}},
		append([]func(*config.Config){bridgeConfig(fb)}, mutate...)...)
	if e.app.Bridge == nil {
		t.Fatal("bridge not enabled")
	}
	return e, logs
}

func (e *env) runBridge() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.app.Bridge.Run(ctx); close(done) }()
	e.t.Cleanup(func() { cancel(); <-done })
}

func outboxLen(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM bridge_outbox`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBridgeAccountLifecycle(t *testing.T) {
	fb := bridgetest.New("bridge-token")
	t.Cleanup(fb.Close)
	e, _ := bridgeEnv(t, fb)
	e.runBridge()
	db := e.sqlDB()

	// Create: a new local account gets its bridge account, no login.
	id := e.registerVerified("Alice", "alice@example.org")
	eventually(t, "alice on the bridge", func() bool { a := fb.Get("alice"); return a != nil && a.Subject == id })
	a := fb.Get("alice")
	if a.Email != "alice@example.org" || a.Nick != "Alice" || a.AltNick != "Alice_" || a.Ident != "alice" || a.Realname != "Alice" || a.Method != "none" || a.Disabled {
		t.Fatalf("alice: %+v", a)
	}

	// Update: display name (API) and email (any path: SQL).
	r := e.login("alice", pw)
	e.expect(r, 200, "")
	e.expect(e.api("PATCH", "/v1/me", map[string]any{"display_name": "Alice Liddell"}, bearer(r.str("access_token"))), 200, "")
	eventually(t, "realname", func() bool { return fb.Get("alice").Realname == "Alice Liddell" })
	if _, err := db.Exec(`UPDATE users SET email = 'alice@new.example' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	eventually(t, "email", func() bool { return fb.Get("alice").Email == "alice@new.example" })

	// Disable / enable (admin API).
	admin := e.adminToken("boss")
	e.expect(e.api("POST", "/v1/admin/users/"+id+"/disable", nil, bearer(admin)), 200, "")
	eventually(t, "disabled", func() bool { return fb.Get("alice").Disabled })
	e.expect(e.api("POST", "/v1/admin/users/"+id+"/enable", nil, bearer(admin)), 200, "")
	eventually(t, "enabled", func() bool { return !fb.Get("alice").Disabled })

	// Rename: the old bridge account goes, the new one keeps the subject.
	if _, err := db.Exec(`UPDATE users SET username = 'Alicia', username_folded = 'alicia' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	eventually(t, "renamed", func() bool {
		n := fb.Get("alicia")
		return fb.Get("alice") == nil && n != nil && n.Subject == id && n.Nick == "Alicia"
	})

	// A federated account (another Boson server's user): method none too.
	if _, err := db.Exec(`INSERT INTO users (id, username, username_folded, display_name) VALUES ('usr_fed1', 'zed', 'zed', 'Zed');
		INSERT INTO federated_accounts (user_id, issuer, subject, home_domain, home_username) VALUES ('usr_fed1', 'https://auth.other.example', 's1', 'other.example', 'zed')`); err != nil {
		t.Fatal(err)
	}
	eventually(t, "federated account", func() bool { z := fb.Get("zed"); return z != nil && z.Subject == "usr_fed1" && z.Method == "none" })

	// Delete.
	if _, err := db.Exec(`DELETE FROM users WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	eventually(t, "deleted", func() bool { return fb.Get("alicia") == nil })
	eventually(t, "outbox drained", func() bool { return outboxLen(t, db) == 0 })

	// A name freed and taken again: a late delete of the old account never
	// removes the new one (subjects differ).
	if _, err := db.Exec(`INSERT INTO users (id, username, username_folded) VALUES ('usr_new', 'alicia', 'alicia')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO bridge_outbox (user_id, username) VALUES ($1, 'Alicia')`, id); err != nil {
		t.Fatal(err)
	}
	eventually(t, "outbox drained", func() bool { return outboxLen(t, db) == 0 })
	if n := fb.Get("alicia"); n == nil || n.Subject != "usr_new" {
		t.Fatalf("new alicia: %+v", n)
	}
}

func TestBridgeOutageThenRetry(t *testing.T) {
	fb := bridgetest.New("bridge-token")
	t.Cleanup(fb.Close)
	e, _ := bridgeEnv(t, fb)
	fb.Down.Store(true)
	e.runBridge()
	db := e.sqlDB()

	id := e.registerVerified("bob", "bob@example.org")
	eventually(t, "retried", func() bool {
		var attempts int
		_ = db.QueryRow(`SELECT coalesce(max(attempts), 0) FROM bridge_outbox WHERE user_id = $1`, id).Scan(&attempts)
		return attempts >= 2
	})
	st := e.internalAPI("GET", "/internal/v1/bridge/status", nil)
	e.expect(st, 200, "")
	if st.body["enabled"] != true || st.body["failing"].(float64) < 1 || !strings.Contains(st.str("last_error"), "503") {
		t.Fatalf("status: %s", st.raw)
	}
	if fb.Get("bob") != nil {
		t.Fatal("bob on a bridge that's down")
	}
	// More changes while it's down: they're kept too.
	if _, err := db.Exec(`UPDATE users SET display_name = 'Bobby' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	fb.Down.Store(false)
	eventually(t, "bob after the outage", func() bool { b := fb.Get("bob"); return b != nil && b.Subject == id && b.Realname == "Bobby" })
	eventually(t, "outbox drained", func() bool { return outboxLen(t, db) == 0 })
}

func TestBridgeReconcile(t *testing.T) {
	fb := bridgetest.New("bridge-token")
	t.Cleanup(fb.Close)
	e, _ := bridgeEnv(t, fb) // the worker isn't running: only the full sync pushes
	carol := e.registerVerified("carol", "carol@example.org")
	dave := e.registerVerified("dave", "dave@example.org")
	// What bridge-sync made: dave up to date (evrd's default login), and an
	// account whose Boson account is gone.
	fb.Seed(bridgetest.Account{Username: "dave", Subject: dave, Email: "dave@example.org", Nick: "dave", AltNick: "dave_", Ident: "dave", Realname: "dave"})
	fb.Seed(bridgetest.Account{Username: "ghost", Subject: "usr_gone"})

	r := e.internalAPI("POST", "/internal/v1/bridge/reconcile", nil)
	e.expect(r, 200, "")
	res := r.body["result"].(map[string]any)
	if r.body["ok"] != true || res["put"].(float64) != 1 || res["deleted"].(float64) != 1 || res["unchanged"].(float64) != 1 {
		t.Fatalf("reconcile: %s", r.raw)
	}
	if got := strings.Join(fb.Names(), ","); got != "carol,dave" {
		t.Fatalf("accounts %s", got)
	}
	if c := fb.Get("carol"); c.Subject != carol || c.Method != "none" {
		t.Fatalf("carol %+v", c)
	}
	if d := fb.Get("dave"); d.Method != "auto" {
		t.Fatalf("an unchanged bridge-sync account got a new login: %+v", d)
	}
	st := e.internalAPI("GET", "/internal/v1/bridge/status", nil)
	if st.str("last_reconcile_at") == "" || st.str("last_reconcile_error") != "" {
		t.Fatalf("status %s", st.raw)
	}
	// The bridge down: 502, and the error is in the status.
	fb.Down.Store(true)
	r = e.internalAPI("POST", "/internal/v1/bridge/reconcile", nil)
	if r.status != 502 || r.body["ok"] != false {
		t.Fatalf("reconcile while down: %d %s", r.status, r.raw)
	}
	st = e.internalAPI("GET", "/internal/v1/bridge/status", nil)
	if !strings.Contains(st.str("last_reconcile_error"), "503") {
		t.Fatalf("status %s", st.raw)
	}
	// Internal token required.
	if r := e.do(e.internal, "POST", "/internal/v1/bridge/reconcile", nil); r.status != 401 {
		t.Fatalf("no token: %d", r.status)
	}
}

// Without BRIDGE_API_URL nothing is queued and the endpoints don't exist.
func TestBridgeOff(t *testing.T) {
	e := newEnv(t)
	db := e.sqlDB()
	e.registerVerified("erin", "erin@example.org")
	if n := outboxLen(t, db); n != 0 {
		t.Fatalf("outbox rows with the bridge off: %d", n)
	}
	if r := e.internalAPI("POST", "/internal/v1/bridge/reconcile", nil); r.status != 404 {
		t.Fatalf("reconcile with the bridge off: %d", r.status)
	}
}

func TestBridgeNickServLogin(t *testing.T) {
	for _, c := range []struct{ name, override, method string }{
		{"default sasl", "", "sasl"},
		{"no SASL on the IRC server", "nickserv", "nickserv"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeServicesRPC(t, "anope-token")
			f.add("Frank", nsPassword, "frank@example.org", true)
			fb := bridgetest.New("bridge-token")
			t.Cleanup(fb.Close)
			e, logs := bridgeEnv(t, fb, func(cfg *config.Config) {
				cfg.AccountsConfig.Backend = config.AccountBackendNickServ
				cfg.NickServConfig = config.NickServConfig{
					Strategy: config.StrategyAnopeRPC, RPCURL: f.srv.URL, RPCToken: "anope-token",
					Timeout: 5 * time.Second, MaxConcurrent: 4, ServiceNick: "NickServ",
					Registration: true, LinkExisting: config.LinkExistingUnclaimed,
					RateAccountBurst: 1000, RateAccountPerMinute: 1000, RateIPBurst: 1000, RateIPPerMinute: 1000,
					LockoutThreshold: 3, LockoutIPThreshold: 100, LockoutWindow: 15 * time.Minute, LockoutDuration: 15 * time.Minute,
				}
				cfg.BridgeConfig.NickServMethod = c.override
			})
			e.runBridge()
			db := e.sqlDB()

			r := e.login("frank", nsPassword)
			e.expect(r, 200, "")
			id := r.str("user", "id")
			eventually(t, "frank's login on the bridge", func() bool { a := fb.Get("frank"); return a != nil && a.Password == nsPassword })
			e.app.Bridge.Wait()
			// The outbox's own push (the new user and link) leaves the login alone.
			eventually(t, "outbox drained", func() bool { return outboxLen(t, db) == 0 })
			a := fb.Get("frank")
			if a.Subject != id || a.Email != "frank@example.org" || a.Nick != "Frank" || a.Method != c.method || a.AuthAccount != "Frank" || a.Password != nsPassword {
				t.Fatalf("frank: %+v", a)
			}
			// The password changed on IRC: the next sign-in hands it on.
			f.mu.Lock()
			f.accounts["frank"] = "changed-" + nsPassword
			f.mu.Unlock()
			e.expect(e.login("frank", "changed-"+nsPassword), 200, "")
			eventually(t, "new password", func() bool { return fb.Get("frank").Password == "changed-"+nsPassword })
			// A full sync leaves the login alone too.
			e.expect(e.internalAPI("POST", "/internal/v1/bridge/reconcile", nil), 200, "")
			if a := fb.Get("frank"); a.Password != "changed-"+nsPassword || a.Method != c.method {
				t.Fatalf("after a full sync: %+v", a)
			}

			// The bridge down at sign-in: retried, then dropped; never logged
			// or stored anywhere in auth.
			fb.Down.Store(true)
			e.expect(e.login("frank", "changed-"+nsPassword), 200, "")
			e.app.Bridge.Wait()
			fb.Down.Store(false)
			for _, pwd := range []string{nsPassword, "changed-" + nsPassword} {
				if strings.Contains(logs.String(), pwd) {
					t.Fatalf("password in the logs: %s", logs)
				}
				var n int
				if err := db.QueryRow(`SELECT (SELECT count(*) FROM bridge_outbox WHERE last_error LIKE '%' || $1 || '%')
					+ (SELECT count(*) FROM bridge_state WHERE last_reconcile_error LIKE '%' || $1 || '%')
					+ (SELECT count(*) FROM audit_log WHERE meta::text LIKE '%' || $1 || '%')`, pwd).Scan(&n); err != nil || n != 0 {
					t.Fatalf("password stored in auth: %d %v", n, err)
				}
			}
			if !strings.Contains(logs.String(), "next sign-in sends it again") {
				t.Fatalf("no drop log: %s", logs)
			}
			for _, call := range fb.Calls() {
				if call.Method == "PUT" && strings.Contains(call.Body, `"auth"`) && !strings.Contains(call.Body, `"password"`) {
					t.Fatalf("a push without the password touched frank's login: %s", call.Body)
				}
			}
		})
	}
}
