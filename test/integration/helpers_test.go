// Package integration runs the HTTP API against a real Postgres.
//
// Set TEST_DATABASE_URL to a database the test user can CREATE DATABASE
// from (each test gets its own throwaway database). Without it these tests
// are skipped. Locally: `make test-integration`.
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	nethttp "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/db"
	authhttp "github.com/boson-chat/auth/http"
	"github.com/boson-chat/auth/internal/mailer"
	"github.com/boson-chat/auth/internal/services/account"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const issuer = "https://auth.integration.test"

// captureMailer records sent messages.
type captureMailer struct {
	mu   sync.Mutex
	msgs []mailer.Message
	ch   chan mailer.Message
}

func newCaptureMailer() *captureMailer { return &captureMailer{ch: make(chan mailer.Message, 100)} }

func (m *captureMailer) Send(_ context.Context, msg mailer.Message) error {
	m.mu.Lock()
	m.msgs = append(m.msgs, msg)
	m.mu.Unlock()
	m.ch <- msg
	return nil
}

func (m *captureMailer) next(t *testing.T) mailer.Message {
	t.Helper()
	select {
	case msg := <-m.ch:
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("no email sent")
		return mailer.Message{}
	}
}

func (m *captureMailer) none(t *testing.T, wait time.Duration) {
	t.Helper()
	select {
	case msg := <-m.ch:
		t.Fatalf("unexpected email to %s: %s", msg.To, msg.Subject)
	case <-time.After(wait):
	}
}

func tokenFromLink(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if q := u.Query(); q.Has("token") || (u.RawQuery != "" && (len(q) != 1 || !q.Has("return_to"))) {
		t.Fatalf("token must be in the fragment, the query only return_to: %s", link)
	}
	v, _ := url.ParseQuery(u.Fragment)
	tok := v.Get("token")
	if tok == "" {
		t.Fatalf("no token in link %s", link)
	}
	return tok
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// env is one isolated service instance.
type env struct {
	t        *testing.T
	app      *authhttp.App
	public   *httptest.Server
	internal *httptest.Server
	mail     *captureMailer
	cfg      config.Config
	client   *nethttp.Client
}

func newEnv(t *testing.T, mutate ...func(*config.Config)) *env {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	dsn := createDatabase(t, base)
	if err := db.MigrateUp(dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	cfg.AppConfig.Env = "test"
	cfg.DBConfig.URL = dsn
	cfg.TokenConfig.KeyEncryptionKey = base64.StdEncoding.EncodeToString(kek)
	cfg.TokenConfig.Issuer = issuer
	cfg.PasswordConfig = config.PasswordConfig{MemoryKiB: 1024, Iterations: 1, Parallelism: 1}
	cfg.HTTPConfig.CookieSecure = false
	cfg.HTTPConfig.PublicURL = "http://auth.integration.test"
	cfg.HTTPConfig.AppURL = "https://app.integration.test"
	cfg.HTTPConfig.TrustedProxies = ""
	cfg.HTTPConfig.CORSAllowedOrigins = "https://app.integration.test"
	cfg.InternalConfig.APIToken = randHex(32)
	cfg.AccountConfig.Registration = config.RegistrationOpen
	cfg.AccountConfig.RequireEmailVerification = true
	cfg.RateLimitConfig = config.RateLimitConfig{Enabled: true, IPBurst: 1000, IPPerMinute: 1000, AccountBurst: 1000, AccountPerMinute: 1000,
		PublicBurst: 1000, PublicPerMinute: 1000}
	cfg.SMTPConfig.Host = ""
	for _, m := range mutate {
		m(&cfg)
	}

	mail := newCaptureMailer()
	app, err := authhttp.Build(context.Background(), cfg, authhttp.Options{Mailer: mail})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := app.Keys.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, app: app, mail: mail, cfg: cfg,
		public: httptest.NewServer(app.Public), internal: httptest.NewServer(app.Internal)}
	jar, _ := cookiejar.New(nil)
	e.client = &nethttp.Client{Jar: jar}
	t.Cleanup(func() {
		e.public.Close()
		e.internal.Close()
		_ = e.app.Close()
	})
	return e
}

// restart rebuilds the app on the same database, the way a deploy starts a
// new process after migrating: pooled connections cache query plans, which
// break when a migration changes a table's columns under them.
func (e *env) restart() {
	e.t.Helper()
	e.public.Close()
	e.internal.Close()
	_ = e.app.Close()
	app, err := authhttp.Build(context.Background(), e.cfg, authhttp.Options{Mailer: e.mail})
	if err != nil {
		e.t.Fatalf("build: %v", err)
	}
	e.app, e.public, e.internal = app, httptest.NewServer(app.Public), httptest.NewServer(app.Internal)
}

func createDatabase(t *testing.T, base string) string {
	t.Helper()
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	name := "auth_it_" + randHex(6)
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)")
		_ = admin.Close()
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

type resp struct {
	status int
	header nethttp.Header
	body   map[string]any
	raw    []byte
}

func (r resp) str(path ...string) string {
	var cur any = r.body
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[p]
	}
	s, _ := cur.(string)
	return s
}

// req options
type opt func(*nethttp.Request)

func bearer(tok string) opt {
	return func(r *nethttp.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}
func header(k, v string) opt { return func(r *nethttp.Request) { r.Header.Set(k, v) } }

func (e *env) do(srv *httptest.Server, method, path string, body any, opts ...opt) resp {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := nethttp.NewRequest(method, srv.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(req)
	}
	res, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{status: res.StatusCode, header: res.Header, raw: raw}
	if len(raw) > 0 && strings.Contains(res.Header.Get("Content-Type"), "json") {
		_ = json.Unmarshal(raw, &out.body)
	}
	return out
}

func (e *env) api(method, path string, body any, opts ...opt) resp {
	e.t.Helper()
	return e.do(e.public, method, path, body, opts...)
}

func (e *env) expect(r resp, status int, code string) {
	e.t.Helper()
	if r.status != status {
		e.t.Fatalf("status %d, want %d: %s", r.status, status, r.raw)
	}
	if code != "" && r.str("error") != code {
		e.t.Fatalf("error %q, want %q: %s", r.str("error"), code, r.raw)
	}
}

const pw = "correct horse battery"

// registerVerified registers a user and verifies its email.
func (e *env) registerVerified(username, email string) string {
	e.t.Helper()
	r := e.api("POST", "/v1/register", map[string]string{"username": username, "email": email, "password": pw})
	e.expect(r, 201, "")
	msg := e.mail.next(e.t)
	e.expect(e.api("POST", "/v1/email/verify", map[string]string{"token": tokenFromLink(e.t, msg.Link)}), 200, "")
	return r.str("user", "id")
}

func (e *env) login(login, password string) resp {
	e.t.Helper()
	return e.api("POST", "/v1/login", map[string]any{"login": login, "password": password})
}

// jwks fetches the published key set and returns a keyfunc for jwt.Parse.
func (e *env) jwksKeyfunc() jwt.Keyfunc {
	e.t.Helper()
	r := e.api("GET", "/.well-known/jwks.json", nil)
	if r.status != 200 {
		e.t.Fatalf("jwks status %d", r.status)
	}
	var set struct {
		Keys []struct {
			Kty, Crv, X, Kid, Alg, Use string
		} `json:"keys"`
	}
	if err := json.Unmarshal(r.raw, &set); err != nil {
		e.t.Fatal(err)
	}
	return func(tk *jwt.Token) (any, error) {
		kid, _ := tk.Header["kid"].(string)
		for _, k := range set.Keys {
			if k.Kid == kid && k.Kty == "OKP" && k.Crv == "Ed25519" {
				b, err := base64.RawURLEncoding.DecodeString(k.X)
				return ed25519.PublicKey(b), err
			}
		}
		return nil, jwt.ErrTokenUnverifiable
	}
}

// adminToken creates an account with the Admin role and returns its access token.
func (e *env) adminToken(username string) string {
	e.t.Helper()
	return e.roleToken(username, "admin")
}

// ownerToken creates an account with the Owner role and returns its access token.
func (e *env) ownerToken(username string) string {
	e.t.Helper()
	return e.roleToken(username, "owner")
}

// roleToken creates an account with role user | admin | owner and logs in.
func (e *env) roleToken(username, role string) string {
	e.t.Helper()
	if _, err := e.app.Account.CreateUser(e.t.Context(), "", account.CreateUserInput{
		Username: username, Email: username + "@example.com", Password: pw, Role: role, EmailVerified: true,
	}); err != nil {
		e.t.Fatal(err)
	}
	r := e.login(username, pw)
	e.expect(r, 200, "")
	return r.str("access_token")
}

func (r resp) list(key string) []map[string]any {
	raw, _ := r.body[key].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, v := range raw {
		m, _ := v.(map[string]any)
		out = append(out, m)
	}
	return out
}
