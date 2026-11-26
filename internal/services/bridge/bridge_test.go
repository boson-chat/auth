package bridge

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/services/bridge/bridgetest"
	"github.com/rs/zerolog"
)

const secret = "hunter2-irc-Secret!"

// memStore is enough Store for the full sync and the login push.
type memStore struct {
	mu    sync.Mutex
	users []User
}

func (m *memStore) SetEnabled(context.Context, bool) error { return nil }
func (m *memStore) Claim(context.Context, int, time.Duration) ([]Change, error) {
	return nil, nil
}
func (m *memStore) Done(context.Context, []int64) error { return nil }
func (m *memStore) Retry(context.Context, []int64, string, func(int) time.Duration) error {
	return nil
}
func (m *memStore) User(_ context.Context, id string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.ID == id {
			return &u, nil
		}
	}
	return nil, nil
}
func (m *memStore) Users(context.Context) ([]User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]User(nil), m.users...), nil
}
func (m *memStore) Pending(context.Context) (int64, error)                      { return 0, nil }
func (m *memStore) LeaseReconcile(context.Context, time.Duration) (bool, error) { return true, nil }
func (m *memStore) ReconcileDone(context.Context, string) error                 { return nil }
func (m *memStore) Status(context.Context) (Status, error)                      { return Status{}, nil }

// syncBuffer is a log sink safe for the push goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newTestService(t *testing.T, url string, st Store, strategy, method string) (*Service, *syncBuffer) {
	t.Helper()
	logs := &syncBuffer{}
	l := zerolog.New(logs).Level(zerolog.DebugLevel)
	cfg := config.BridgeConfig{APIURL: url, Token: "tok", NickServMethod: method, PollInterval: time.Second,
		RetryMin: time.Millisecond, RetryMax: 10 * time.Millisecond, Timeout: 2 * time.Second}
	s := New(Deps{Client: NewHTTPClient(url, "tok", time.Second, nil), Store: st, Config: cfg, Strategy: strategy, Log: &l,
		CredentialRetries: []time.Duration{20 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond}})
	t.Cleanup(s.Close)
	return s, logs
}

// The mapping is bridge-sync's (stack images/bridgesync/sync_test.go).
func TestWantMatchesBridgeSync(t *testing.T) {
	if n, ok := Name("Alice"); !ok || n != "alice" {
		t.Fatalf("Name(Alice) = %q %v", n, ok)
	}
	for _, bad := range []string{"9bad", "a", "x[y]", "under_score_is_fine_but_this_is_too_long_33"} {
		if _, ok := Name(bad); ok {
			t.Fatalf("Name(%q) accepted", bad)
		}
	}
	a := Want(User{ID: "usr_a", Username: "Alice", Email: "a@x"})
	if a.Subject != "usr_a" || a.Nick != "Alice" || a.AltNick != "Alice_" || a.Ident != "alice" || a.Realname != "Alice" || a.Email != "a@x" || a.Auth != nil {
		t.Fatalf("alice: %+v", a)
	}
	b := Want(User{ID: "usr_b", Username: "bob_the_builder_9", DisplayName: "Bob", Disabled: true})
	if !b.Disabled || b.Ident != "bobthebuil" || b.Realname != "Bob" {
		t.Fatalf("bob: %+v", b)
	}
	if c := Want(User{ID: "usr_c", Username: "__"}); c.Ident != "boson" {
		t.Fatalf("ident fallback: %+v", c)
	}
	if n := Want(User{ID: "usr_n", Username: "carol", NickServAccount: "Carol"}); n.Nick != "Carol" || n.AltNick != "Carol_" {
		t.Fatalf("NickServ nick: %+v", n)
	}
}

func TestBodyLeavesLogins(t *testing.T) {
	local := User{ID: "usr_a", Username: "alice"}
	// New: method none.
	if b := body(local, nil); b == nil || b.Auth == nil || b.Auth.Method != "none" {
		t.Fatalf("new local: %+v", b)
	}
	// bridge-sync's accounts (evrd's default auto, no password): untouched.
	cur := &Account{Username: "alice", Subject: "usr_a", Nick: "alice", AltNick: "alice_", Ident: "alice", Realname: "alice", Auth: AuthView{Method: "auto"}}
	if b := body(local, cur); b != nil {
		t.Fatalf("unchanged account pushed: %+v", b)
	}
	// A login it shouldn't have: cleared.
	cur.Auth = AuthView{Method: "sasl", HasPassword: true}
	if b := body(local, cur); b == nil || b.Auth == nil || b.Auth.Method != "none" {
		t.Fatalf("stale login kept: %+v", b)
	}
	// NickServ accounts: the login is the sign-in's business.
	ns := User{ID: "usr_a", Username: "alice", NickServAccount: "alice"}
	cur.Auth = AuthView{Method: "sasl", Account: "alice", HasPassword: true}
	if b := body(ns, cur); b != nil {
		t.Fatalf("NickServ account pushed: %+v", b)
	}
	if b := body(ns, nil); b == nil || b.Auth != nil {
		t.Fatalf("new NickServ account: %+v", b)
	}
}

func TestMethod(t *testing.T) {
	for _, c := range []struct{ strategy, override, want string }{
		{config.StrategyAnopeRPC, "", "sasl"},
		{config.StrategySASL, "", "sasl"},
		{config.StrategyAthemeJSONRPC, "", "sasl"},
		{config.StrategyIdentify, "", "nickserv"},
		{config.StrategyAthemeJSONRPC, "nickserv", "nickserv"},
		{config.StrategyIdentify, "AUTO", "auto"},
	} {
		if got := (config.BridgeConfig{NickServMethod: c.override}).Method(c.strategy); got != c.want {
			t.Errorf("%s/%q: %s, want %s", c.strategy, c.override, got, c.want)
		}
	}
}

func nsUser(id, name string) *user.User {
	email := name + "@example.org"
	return &user.User{ID: id, Username: name, Email: &email, DisplayName: "The " + name}
}

func TestAccountSignedInHandsOverTheLogin(t *testing.T) {
	for _, c := range []struct{ strategy, method string }{
		{config.StrategyAnopeRPC, "sasl"},
		{config.StrategyIdentify, "nickserv"},
	} {
		t.Run(c.strategy, func(t *testing.T) {
			fb := bridgetest.New("tok")
			defer fb.Close()
			s, logs := newTestService(t, fb.URL(), &memStore{}, c.strategy, "")
			if err := s.AccountSignedIn(context.Background(), nsUser("usr_1", "Dana"), "Dana", secret); err != nil {
				t.Fatal(err)
			}
			s.Wait()
			a := fb.Get("dana")
			if a == nil || a.Subject != "usr_1" || a.Email != "Dana@example.org" || a.Nick != "Dana" || a.Realname != "The Dana" ||
				a.Method != c.method || a.AuthAccount != "Dana" || a.Password != secret {
				t.Fatalf("bridge account: %+v", a)
			}
			// A new password on the next sign-in reaches the bridge.
			if err := s.AccountSignedIn(context.Background(), nsUser("usr_1", "Dana"), "Dana", "new-"+secret); err != nil {
				t.Fatal(err)
			}
			s.Wait()
			if a := fb.Get("dana"); a.Password != "new-"+secret {
				t.Fatalf("password change didn't reach the bridge: %+v", a)
			}
			if strings.Contains(logs.String(), secret) {
				t.Fatalf("password in the logs: %s", logs)
			}
		})
	}
}

func TestAccountSignedInRetriesAndNeverLogsThePassword(t *testing.T) {
	fb := bridgetest.New("tok")
	defer fb.Close()
	// A bridge that first fails and echoes what it got (the worst case for logs).
	var mu sync.Mutex
	fails := 3
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		f := fails > 0 && r.Method == http.MethodPut
		if f {
			fails--
		}
		mu.Unlock()
		if f {
			var b bytes.Buffer
			_, _ = b.ReadFrom(r.Body)
			http.Error(w, `{"error":"rejected `+strings.ReplaceAll(b.String(), `"`, `'`)+`"}`, http.StatusUnprocessableEntity)
			return
		}
		fb.ServeHTTP(w, r)
	}))
	defer srv.Close()
	s, logs := newTestService(t, srv.URL, &memStore{}, config.StrategyAnopeRPC, "")
	if err := s.AccountSignedIn(context.Background(), nsUser("usr_2", "erin"), "erin", secret); err != nil {
		t.Fatal(err)
	}
	s.Wait()
	if a := fb.Get("erin"); a == nil || a.Password != secret || a.Method != "sasl" {
		t.Fatalf("after retries: %+v", a)
	}
	out := logs.String()
	if !strings.Contains(out, "will retry") || !strings.Contains(out, "[redac") {
		t.Fatalf("expected retry logs with the echo redacted: %s", out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("password in the logs: %s", out)
	}

	// Down for good: dropped after the retries, still never logged.
	fb.Down.Store(true)
	if err := s.AccountSignedIn(context.Background(), nsUser("usr_2", "erin"), "erin", "other-"+secret); err != nil {
		t.Fatal(err)
	}
	s.Wait()
	out = logs.String()
	if !strings.Contains(out, "next sign-in sends it again") || strings.Contains(out, secret) {
		t.Fatalf("drop log: %s", out)
	}
}

func TestErrorTextRedacts(t *testing.T) {
	got := errorText([]byte(`{"error":"bad password `+secret+`\nline two"}`), secret)
	if strings.Contains(got, secret) || strings.Contains(got, "\n") || !strings.Contains(got, "[redacted]") {
		t.Fatalf("errorText = %q", got)
	}
	if s := (Auth{Method: "sasl", Account: "a", Password: secret}).String(); strings.Contains(s, secret) {
		t.Fatalf("Auth.String shows the password: %s", s)
	}
}

func TestReconcile(t *testing.T) {
	fb := bridgetest.New("tok")
	defer fb.Close()
	// What bridge-sync left: an up-to-date account, a stale one, a renamed one.
	fb.Seed(bridgetest.Account{Username: "alice", Subject: "usr_a", Email: "a@x", Nick: "Alice", AltNick: "Alice_", Ident: "alice", Realname: "Alice"})
	fb.Seed(bridgetest.Account{Username: "stale", Subject: "usr_gone"})
	fb.Seed(bridgetest.Account{Username: "oldname", Subject: "usr_r", Nick: "oldname"})
	st := &memStore{users: []User{
		{ID: "usr_a", Username: "Alice", Email: "a@x"},
		{ID: "usr_b", Username: "bob_the_builder_9", Disabled: true},
		{ID: "usr_c", Username: "9bad"},
		{ID: "usr_r", Username: "newname"},
	}}
	s, _ := newTestService(t, fb.URL(), st, "", "")
	res, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Users != 4 || res.Put != 2 || res.Deleted != 2 || res.Unchanged != 1 || res.Skipped != 1 || res.Failed != 0 {
		t.Fatalf("result %+v", res)
	}
	if got := strings.Join(fb.Names(), ","); got != "alice,bob_the_builder_9,newname" {
		t.Fatalf("accounts %s", got)
	}
	if a := fb.Get("alice"); a.Method != "auto" {
		t.Fatalf("bridge-sync's account got a new login: %+v", a)
	}
	if b := fb.Get("bob_the_builder_9"); !b.Disabled || b.Ident != "bobthebuil" || b.Method != "none" {
		t.Fatalf("bob %+v", b)
	}
	// Again: nothing to do.
	fb.Calls()
	if res, err := s.Reconcile(context.Background()); err != nil || res.Put+res.Deleted != 0 {
		t.Fatalf("second run %+v %v", res, err)
	}
	for _, c := range fb.Calls() {
		if c.Method != http.MethodGet {
			t.Fatalf("second run wrote: %+v", c)
		}
	}
	// Bridge down: an error, nothing lost.
	fb.Down.Store(true)
	if _, err := s.Reconcile(context.Background()); err == nil {
		t.Fatal("no error with the bridge down")
	}
}
