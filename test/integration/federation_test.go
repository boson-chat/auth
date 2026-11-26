package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	authhttp "github.com/boson-chat/auth/http"
	idgen "github.com/boson-chat/auth/internal/ids"
	"github.com/golang-jwt/jwt/v5"
)

// fakeNet is a fake internet for federation: one TLS server that routes by
// Host, a CA the remote trusts, and a client that dials every name to it.
// So https://home.test/.well-known/boson.json, https://auth.home.test/...
// and https://directory.test/... are real HTTPS requests.
type fakeNet struct {
	t      *testing.T
	srv    *httptest.Server
	client *nethttp.Client
	mu     sync.Mutex
	hosts  map[string]nethttp.Handler
}

func newFakeNet(t *testing.T) *fakeNet {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fake"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames:    []string{"*.test", "*.home.test", "*.remote.test", "*.other.test", "*.evil.test"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	n := &fakeNet{t: t, hosts: map[string]nethttp.Handler{}}
	n.srv = httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host, _, _ := strings.Cut(r.Host, ":")
		n.mu.Lock()
		h := n.hosts[host]
		n.mu.Unlock()
		if h == nil {
			nethttp.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	}))
	n.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	n.srv.StartTLS()
	t.Cleanup(n.srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	addr := n.srv.Listener.Addr().String()
	n.client = &nethttp.Client{Timeout: 5 * time.Second, Transport: &nethttp.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	return n
}

func (n *fakeNet) handle(host string, h nethttp.Handler) {
	n.mu.Lock()
	n.hosts[host] = h
	n.mu.Unlock()
}

// fakeDirectory answers GET /v1/networks/lookup like the Boson directory
// does for anonymous callers: verified listings only, 404 otherwise.
type fakeDirectory struct {
	mu       sync.Mutex
	verified map[string]bool
	lookups  atomic.Int64
}

func (d *fakeDirectory) set(host string, ok bool) {
	d.mu.Lock()
	d.verified[host] = ok
	d.mu.Unlock()
}

func (d *fakeDirectory) ServeHTTP(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.URL.Path != "/v1/networks/lookup" {
		nethttp.NotFound(w, r)
		return
	}
	d.lookups.Add(1)
	h := r.URL.Query().Get("hostname")
	d.mu.Lock()
	ok := d.verified[h]
	d.mu.Unlock()
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"error":"not_found","message":"not found","code":"not_found"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"network": map[string]any{
		"id": "net_1", "hostname": h, "port": 6697, "tls": true, "name": h, "status": "verified",
	}, "verification": nil})
}

// fakeFiles is the files service's internal quota API.
type fakeFiles struct {
	mu    sync.Mutex
	calls []string // "PUT usr_… {body}" / "DELETE usr_…"
	token string
}

func (f *fakeFiles) ServeHTTP(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Header.Get("X-Internal-Token") != f.token || !strings.HasPrefix(r.URL.Path, "/internal/quota/") {
		w.WriteHeader(401)
		return
	}
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, strings.TrimSpace(r.Method+" "+strings.TrimPrefix(r.URL.Path, "/internal/quota/")+" "+string(b)))
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{}`)
}

func (f *fakeFiles) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// clock is an adjustable clock for an env.
type clock struct{ offset atomic.Int64 }

func (c *clock) now() time.Time            { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *clock) advance(d time.Duration)   { c.offset.Add(int64(d)) }
func (c *clock) options() authhttp.Options { return authhttp.Options{Now: c.now} }

// fed is a home and a remote auth instance (separate databases and keys)
// on the fake net, plus the home domain's boson.json and a directory.
type fed struct {
	t          *testing.T
	net        *fakeNet
	home       *env
	remote     *env
	dir        *fakeDirectory
	files      *fakeFiles
	remoteTime *clock
	// discovery overrides home.test's boson.json (nil: the real one).
	discovery atomic.Pointer[map[string]any]
}

const (
	homeIssuer   = "https://auth.home.test"
	remoteIssuer = "https://auth.remote.test"
)

func newFed(t *testing.T, remoteMutate ...func(*config.Config)) *fed {
	t.Helper()
	f := &fed{t: t, net: newFakeNet(t), dir: &fakeDirectory{verified: map[string]bool{}}, remoteTime: &clock{}}
	f.files = &fakeFiles{token: randHex(16)}
	filesSrv := httptest.NewServer(f.files)
	t.Cleanup(filesSrv.Close)

	f.home = newEnv(t, func(c *config.Config) {
		c.TokenConfig.Issuer = homeIssuer
		c.HTTPConfig.PublicURL = homeIssuer
		c.FederationConfig.Domain = "home.test"
		c.FederationConfig.Mode = config.FederationOpen
		c.FederationConfig.AssertBurst, c.FederationConfig.AssertPerMinute = 1000, 1000
	})
	ro := f.remoteTime.options()
	ro.FederationHTTPClient = f.net.client
	f.remote = newEnvOpts(t, ro, append([]func(*config.Config){func(c *config.Config) {
		c.TokenConfig.Issuer = remoteIssuer
		c.HTTPConfig.PublicURL = remoteIssuer
		c.FederationConfig.Domain = "remote.test"
		c.FederationConfig.Mode = config.FederationDirectory
		c.FederationConfig.DirectoryURL = "https://directory.test"
		c.FederationConfig.Allow, c.FederationConfig.Block = "", ""
		c.FederationConfig.RemoteRole = "Remote"
		c.FederationConfig.RemoteVoice = true
		c.FederationConfig.RemoteUploadQuota = "1GB"
		c.FederationConfig.RemoteMaxFile = ""
		c.FilesInternalConfig = config.FilesInternalConfig{URL: filesSrv.URL, Token: f.files.token}
	}}, remoteMutate...)...)

	f.net.handle("auth.home.test", f.home.app.Public)
	f.net.handle("directory.test", f.dir)
	f.net.handle("home.test", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.URL.Path != "/.well-known/boson.json" {
			nethttp.NotFound(w, r)
			return
		}
		doc := map[string]any{"version": 1, "irc": map[string]any{"host": "irc.home.test", "port": 6697, "tls": true},
			"auth": map[string]any{"url": homeIssuer}}
		if o := f.discovery.Load(); o != nil {
			doc = *o
		} else {
			// What the stack's wellknown service publishes: auth's metadata
			// as the federation section.
			md := f.home.api("GET", "/.well-known/boson-federation.json", nil)
			if md.status != 200 {
				t.Errorf("home metadata: %d %s", md.status, md.raw)
			}
			doc["federation"] = md.body
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	return f
}

// homeUser registers and signs in a user at the home, returning its access token.
func (f *fed) homeUser(username string) string {
	f.t.Helper()
	f.home.registerVerified(username, username+"@home.example")
	r := f.home.login(username, pw)
	f.home.expect(r, 200, "")
	return r.str("access_token")
}

func (f *fed) assertion(homeToken, audience string) string {
	f.t.Helper()
	r := f.home.api("POST", "/v1/federation/assertions", map[string]string{"audience": audience}, bearer(homeToken))
	f.home.expect(r, 200, "")
	return r.str("assertion")
}

func (f *fed) login(assertion string) resp {
	f.t.Helper()
	return f.remote.api("POST", "/v1/federation/login", map[string]string{"assertion": assertion})
}

// signAsHome signs claims with the home's current signing key, for
// assertions the home itself would never issue.
func (f *fed) signAsHome(header map[string]any, claims jwt.MapClaims) string {
	f.t.Helper()
	kid, priv, err := f.home.app.Keys.SigningKey(f.t.Context())
	if err != nil {
		f.t.Fatal(err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = "boson-fed+jwt"
	for k, v := range header {
		tok.Header[k] = v
	}
	s, err := tok.SignedString(priv)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fed) claims(sub, username string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": homeIssuer, "sub": sub, "aud": remoteIssuer, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"jti": idgen.New(idgen.TokenID), "boson_domain": "home.test", "preferred_username": username, "name": username,
		"email_verified": true,
	}
}

func TestFederationFullFlow(t *testing.T) {
	f := newFed(t)
	f.dir.set("home.test", true)

	// Both servers publish their metadata.
	md := f.remote.api("GET", "/.well-known/boson-federation.json", nil)
	f.remote.expect(md, 200, "")
	if md.str("issuer") != remoteIssuer || md.str("accepts") != "directory" ||
		md.str("login_endpoint") != remoteIssuer+"/v1/federation/login" ||
		md.str("assertion_endpoint") != remoteIssuer+"/v1/federation/assertions" ||
		md.str("jwks_uri") != remoteIssuer+"/.well-known/jwks.json" || md.body["version"] != float64(1) {
		t.Fatalf("metadata: %s", md.raw)
	}
	if md.header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("metadata CORS: %v", md.header)
	}

	homeTok := f.homeUser("alice")
	f.home.expect(f.home.api("PATCH", "/v1/me", map[string]string{"display_name": "Alice A."}, bearer(homeTok)), 200, "")

	// Home side: the assertion.
	r := f.home.api("POST", "/v1/federation/assertions", map[string]string{"audience": remoteIssuer}, bearer(homeTok))
	f.home.expect(r, 200, "")
	if r.body["expires_in"].(float64) > 300 || r.body["expires_in"].(float64) < 290 {
		t.Fatalf("expires_in: %s", r.raw)
	}
	assertion := r.str("assertion")
	var c jwt.MapClaims
	tok, err := jwt.ParseWithClaims(assertion, &c, f.home.jwksKeyfunc(), jwt.WithAudience(remoteIssuer))
	if err != nil {
		t.Fatal(err)
	}
	if tok.Header["typ"] != "boson-fed+jwt" || tok.Header["alg"] != "EdDSA" || tok.Header["kid"] == "" {
		t.Fatalf("header: %v", tok.Header)
	}
	if c["iss"] != homeIssuer || c["aud"] != remoteIssuer || c["boson_domain"] != "home.test" || c["preferred_username"] != "alice" ||
		c["name"] != "Alice A." || c["email_verified"] != true || c["jti"] == "" || c["exp"].(float64)-c["iat"].(float64) != 300 {
		t.Fatalf("claims: %v", c)
	}
	if _, ok := c["email"]; ok {
		t.Fatal("assertion carries the email")
	}
	homeID, _ := c["sub"].(string)

	// Remote side: the login.
	lr := f.login(assertion)
	f.remote.expect(lr, 200, "")
	if lr.body["federated"] != true || lr.str("identity") != "alice@home.test" || lr.str("handle") != "alice" ||
		lr.str("access_token") == "" || lr.str("refresh_token") == "" || lr.str("user", "username") != "alice" ||
		lr.str("user", "display_name") != "Alice A." || lr.str("user", "email") != "" {
		t.Fatalf("login: %s", lr.raw)
	}
	at := lr.str("access_token")
	remoteUserID := lr.str("user", "id")

	// The remote's access token is an ordinary one: what Ergo's authscript
	// (IRCV3BEARER / OAUTHBEARER) checks is typ at+jwt, aud boson, the
	// remote's iss and name = the IRC account name.
	var ac jwt.MapClaims
	atok, err := jwt.ParseWithClaims(at, &ac, f.remote.jwksKeyfunc(), jwt.WithAudience("boson"), jwt.WithIssuer(remoteIssuer))
	if err != nil {
		t.Fatal(err)
	}
	if atok.Header["typ"] != "at+jwt" || ac["name"] != "alice" || ac["sub"] != remoteUserID {
		t.Fatalf("access token: %v %v", atok.Header, ac)
	}
	roles, _ := ac["roles"].([]any)
	if len(roles) != 1 || roles[0] != "Remote" {
		t.Fatalf("roles claim: %v", ac["roles"])
	}

	me := f.remote.api("GET", "/v1/me", nil, bearer(at))
	f.remote.expect(me, 200, "")
	if me.str("federation", "identity") != "alice@home.test" || me.str("federation", "home_domain") != "home.test" ||
		me.str("federation", "issuer") != homeIssuer {
		t.Fatalf("me: %s", me.raw)
	}
	if home := f.home.api("GET", "/v1/me", nil, bearer(homeTok)); home.body["federation"] != nil {
		t.Fatalf("home me federation: %s", home.raw)
	}

	// IRC: Ergo's grants lookup for logins without a password.
	irc := f.remote.do(f.remote.internal, "GET", "/internal/v1/users/alice/irc", nil, header("X-Internal-Token", f.remote.cfg.InternalConfig.APIToken))
	f.remote.expect(irc, 200, "")
	if irc.str("user_id") != remoteUserID || irc.body["disabled"] != false {
		t.Fatalf("irc: %s", irc.raw)
	}
	// No password login, locally or over SASL PLAIN.
	f.remote.expect(f.remote.login("alice", pw), 401, "invalid_credentials")
	vp := f.remote.do(f.remote.internal, "POST", "/internal/v1/verify-password", map[string]string{"username": "alice", "password": pw},
		header("X-Internal-Token", f.remote.cfg.InternalConfig.APIToken))
	if vp.status != 200 || vp.body["ok"] != false {
		t.Fatalf("verify-password: %d %s", vp.status, vp.raw)
	}
	// Voice tokens like a local user's.
	v := f.remote.api("POST", "/v1/voice/token", map[string]any{"rooms": []string{"#lobby"}}, bearer(at))
	f.remote.expect(v, 200, "")
	// Password reset doesn't apply.
	adm := f.remote.adminToken("radmin")
	f.remote.expect(f.remote.api("POST", "/v1/admin/users/"+remoteUserID+"/password-reset", nil, bearer(adm)), 409, "federated_account")
	// A federated account can't federate onwards.
	f.remote.expect(f.remote.api("POST", "/v1/federation/assertions", map[string]string{"audience": "https://auth.other.test"}, bearer(at)), 403, "federated_account")

	// Upload quota pushed to files once.
	if calls := f.files.list(); len(calls) != 1 || calls[0] != "PUT "+remoteUserID+` {"max_file_bytes":null,"quota_bytes":1000000000}` {
		t.Fatalf("files calls: %v", calls)
	}

	// Signing in again: same account, profile refreshed, quota not re-pushed.
	f.home.expect(f.home.api("PATCH", "/v1/me", map[string]string{"display_name": "Alice B."}, bearer(homeTok)), 200, "")
	lr2 := f.login(f.assertion(homeTok, remoteIssuer))
	f.remote.expect(lr2, 200, "")
	if lr2.str("user", "id") != remoteUserID || lr2.str("user", "display_name") != "Alice B." || lr2.str("handle") != "alice" {
		t.Fatalf("second login: %s", lr2.raw)
	}
	if calls := f.files.list(); len(calls) != 1 {
		t.Fatalf("quota pushed again: %v", calls)
	}
	// Settings change → pushed at the next sign-in.
	f.remote.expect(f.remote.api("PATCH", "/v1/admin/federation", map[string]any{"remote_upload_quota": ""}, bearer(adm)), 200, "")
	f.remote.expect(f.login(f.assertion(homeTok, remoteIssuer)), 200, "")
	if calls := f.files.list(); len(calls) != 2 || calls[1] != "DELETE "+remoteUserID {
		t.Fatalf("files calls after reset: %v", calls)
	}

	// Admin list of remote users.
	ul := f.remote.api("GET", "/v1/admin/federation/users", nil, bearer(adm))
	f.remote.expect(ul, 200, "")
	users := ul.list("users")
	if len(users) != 1 || users[0]["identity"] != "alice@home.test" || users[0]["handle"] != "alice" ||
		users[0]["home_domain"] != "home.test" || users[0]["subject"] != homeID || users[0]["last_seen_at"] == nil ||
		users[0]["banned"] != false || ul.body["total"] != float64(1) {
		t.Fatalf("remote users: %s", ul.raw)
	}
	one := f.remote.api("GET", "/v1/admin/federation/users/"+remoteUserID, nil, bearer(adm))
	f.remote.expect(one, 200, "")
	f.remote.expect(f.remote.api("GET", "/v1/admin/federation/users/"+f.remote.app.Config.TokenConfig.Issuer, nil, bearer(adm)), 404, "")
	// Members can't see it.
	f.remote.expect(f.remote.api("GET", "/v1/admin/federation/users", nil, bearer(at)), 403, "forbidden")

	// Disabling the federated account locally stops its sign-ins.
	f.remote.expect(f.remote.api("POST", "/v1/admin/users/"+remoteUserID+"/disable", nil, bearer(adm)), 200, "")
	f.remote.expect(f.login(f.assertion(homeTok, remoteIssuer)), 403, "account_disabled")
}

func TestFederationDisabledHomeUser(t *testing.T) {
	f := newFed(t)
	f.dir.set("home.test", true)
	homeTok := f.homeUser("dave")
	adm := f.home.adminToken("hadmin")
	me := f.home.api("GET", "/v1/me", nil, bearer(homeTok))
	f.home.expect(f.home.api("POST", "/v1/admin/users/"+me.str("user", "id")+"/disable", nil, bearer(adm)), 200, "")
	r := f.home.api("POST", "/v1/federation/assertions", map[string]string{"audience": remoteIssuer}, bearer(homeTok))
	if r.status != 401 && r.status != 403 {
		t.Fatalf("assertion for a disabled user: %d %s", r.status, r.raw)
	}
	// Bad audiences.
	tok := f.homeUser("erin")
	f.home.expect(f.home.api("POST", "/v1/federation/assertions", map[string]string{"audience": "not a url"}, bearer(tok)), 400, "invalid_request")
	f.home.expect(f.home.api("POST", "/v1/federation/assertions", map[string]string{"audience": "http://auth.remote.test"}, bearer(tok)), 400, "invalid_request")
	f.home.expect(f.home.api("POST", "/v1/federation/assertions", map[string]string{"audience": homeIssuer}, bearer(tok)), 400, "invalid_request")
	f.home.expect(f.home.api("POST", "/v1/federation/assertions", map[string]string{"audience": remoteIssuer}), 401, "unauthenticated")
}

func TestFederationAssertionRateLimit(t *testing.T) {
	home := newEnv(t, func(c *config.Config) {
		c.TokenConfig.Issuer, c.HTTPConfig.PublicURL = homeIssuer, homeIssuer
		c.FederationConfig.Domain = "home.test"
		c.FederationConfig.AssertBurst, c.FederationConfig.AssertPerMinute = 2, 1
	})
	home.registerVerified("alice", "alice@home.example")
	tok := home.login("alice", pw).str("access_token")
	for i := range 3 {
		r := home.api("POST", "/v1/federation/assertions", map[string]string{"audience": remoteIssuer}, bearer(tok))
		if want := map[bool]int{true: 200, false: 429}[i < 2]; r.status != want {
			t.Fatalf("assertion %d: %d %s", i, r.status, r.raw)
		}
	}
}

func TestFederationTrustModes(t *testing.T) {
	f := newFed(t)
	homeTok := f.homeUser("bob")
	adm := f.remote.adminToken("radmin")
	set := func(patch map[string]any) {
		t.Helper()
		f.remote.expect(f.remote.api("PATCH", "/v1/admin/federation", patch, bearer(adm)), 200, "")
	}
	try := func(status int, code string) resp {
		t.Helper()
		r := f.login(f.assertion(homeTok, remoteIssuer))
		f.remote.expect(r, status, code)
		return r
	}

	// directory (default): not listed → refused; the directory's answer
	// is cached, so a new listing counts after the cache expires.
	r := try(403, "domain_not_trusted")
	if !strings.Contains(r.str("message"), "verified") {
		t.Fatalf("message: %s", r.raw)
	}
	f.dir.set("irc.home.test", true) // boson.json's irc.host (a subdomain) counts too
	f.remoteTime.advance(3 * time.Minute)
	try(200, "")
	lookups := f.dir.lookups.Load()
	try(200, "")
	if f.dir.lookups.Load() != lookups {
		t.Fatal("directory lookup not cached")
	}

	// allowlist
	set(map[string]any{"mode": "allowlist", "allow": []string{}})
	try(403, "domain_not_trusted")
	set(map[string]any{"allow": []string{"*.example.org", "home.test"}})
	try(200, "")
	set(map[string]any{"allow": []string{"*.home.test"}}) // wildcard: the domain and its subdomains
	try(200, "")

	// open: anything with valid discovery, listed or not.
	f.dir.set("irc.home.test", false)
	set(map[string]any{"mode": "open"})
	try(200, "")

	// off: refuse, and stop issuing as a home.
	set(map[string]any{"mode": "off"})
	try(403, "federation_off")
	md := f.remote.api("GET", "/.well-known/boson-federation.json", nil)
	if md.str("accepts") != "off" {
		t.Fatalf("metadata: %s", md.raw)
	}
	rt := f.remote.login("radmin", pw)
	f.remote.expect(f.remote.api("POST", "/v1/federation/assertions", map[string]string{"audience": homeIssuer}, bearer(rt.str("access_token"))), 403, "federation_off")

	// A home whose boson.json says off is refused too.
	set(map[string]any{"mode": "open"})
	md2 := f.home.api("GET", "/.well-known/boson-federation.json", nil)
	fedSection := md2.body
	fedSection["accepts"] = "off"
	f.discovery.Store(&map[string]any{"version": 1, "federation": fedSection})
	f.remoteTime.advance(20 * time.Minute) // past the discovery cache
	try(502, "discovery_failed")
	// Discovery gone.
	f.discovery.Store(&map[string]any{"version": 1})
	f.remoteTime.advance(20 * time.Minute)
	try(502, "discovery_failed")
	// Discovery naming another issuer.
	fedSection["accepts"] = "open"
	fedSection["issuer"] = "https://auth.evil.test"
	f.discovery.Store(&map[string]any{"version": 1, "federation": fedSection})
	f.remoteTime.advance(20 * time.Minute)
	try(401, "bad_assertion")

	// Reset to env defaults with null (a fresh token: the clock moved on).
	adm = f.remote.login("radmin", pw).str("access_token")
	set(map[string]any{"mode": nil, "allow": nil})
	st := f.remote.api("GET", "/v1/admin/federation", nil, bearer(adm))
	for k, v := range st.body["sources"].(map[string]any) {
		if v == "database" {
			t.Fatalf("%s still from the database: %s", k, st.raw)
		}
	}
	if st.str("mode") != "directory" || st.body["editable"] != true || st.str("issuer") != remoteIssuer || st.str("domain") != "remote.test" ||
		st.body["remote_users"] != float64(1) {
		t.Fatalf("settings: %s", st.raw)
	}
	f.remote.expect(f.remote.api("PATCH", "/v1/admin/federation", map[string]any{"mode": "sometimes"}, bearer(adm)), 400, "invalid_request")
	f.remote.expect(f.remote.api("PATCH", "/v1/admin/federation", map[string]any{"domain": "x.test"}, bearer(adm)), 400, "invalid_request")
	f.remote.expect(f.remote.api("PATCH", "/v1/admin/federation", map[string]any{"block": []string{"not a domain"}}, bearer(adm)), 400, "invalid_request")
}

func TestFederationEnvAllowAndBlock(t *testing.T) {
	f := newFed(t, func(c *config.Config) {
		c.FederationConfig.Mode = config.FederationAllowlist
		c.FederationConfig.Allow = "home.test"
	})
	homeTok := f.homeUser("carol")
	f.remote.expect(f.login(f.assertion(homeTok, remoteIssuer)), 200, "")

	g := newFed(t, func(c *config.Config) {
		c.FederationConfig.Mode = config.FederationOpen
		c.FederationConfig.Block = "*.home.test"
	})
	tok := g.homeUser("carol")
	g.remote.expect(g.login(g.assertion(tok, remoteIssuer)), 403, "domain_blocked")
}

func TestFederationBlockAndBan(t *testing.T) {
	f := newFed(t)
	f.dir.set("home.test", true)
	adm := f.remote.adminToken("radmin")
	aliceTok, bobTok := f.homeUser("alice"), f.homeUser("bob")
	al := f.login(f.assertion(aliceTok, remoteIssuer))
	f.remote.expect(al, 200, "")
	bl := f.login(f.assertion(bobTok, remoteIssuer))
	f.remote.expect(bl, 200, "")
	aliceID := al.str("user", "id")
	internal := header("X-Internal-Token", f.remote.cfg.InternalConfig.APIToken)

	// Ban alice: sessions end, sign-in refused, IRC drops the account.
	b := f.remote.api("POST", "/v1/admin/federation/users/"+aliceID+"/ban", map[string]string{"reason": "spam"}, bearer(adm))
	f.remote.expect(b, 200, "")
	if b.body["banned"] != true || b.str("ban_reason") != "spam" || b.str("banned_at") == "" || b.body["sessions"] != float64(0) ||
		b.body["disabled"] != true || b.str("id") != aliceID {
		t.Fatalf("ban: %s", b.raw)
	}
	f.remote.expect(f.remote.api("GET", "/v1/me", nil, bearer(al.str("access_token"))), 401, "")
	f.remote.expect(f.remote.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": al.str("refresh_token")}), 401, "")
	f.remote.expect(f.login(f.assertion(aliceTok, remoteIssuer)), 403, "identity_banned")
	rm := f.remote.do(f.remote.internal, "GET", "/internal/v1/irc/accounts/removed", nil, internal)
	if !strings.Contains(string(rm.raw), `"username":"alice","reason":"disabled"`) {
		t.Fatalf("removed feed: %s", rm.raw)
	}
	bans := f.remote.api("GET", "/v1/admin/federation/bans", nil, bearer(adm))
	if l := bans.list("bans"); len(l) != 1 || l[0]["identity"] != "alice@home.test" || l[0]["reason"] != "spam" {
		t.Fatalf("bans: %s", bans.raw)
	}
	// bob is unaffected.
	f.remote.expect(f.remote.api("GET", "/v1/me", nil, bearer(bl.str("access_token"))), 200, "")
	// Unban: alice signs in again.
	ub := f.remote.api("DELETE", "/v1/admin/federation/users/"+aliceID+"/ban", nil, bearer(adm))
	f.remote.expect(ub, 200, "")
	if ub.body["banned"] != false || ub.body["disabled"] != false {
		t.Fatalf("unban: %s", ub.raw)
	}
	al = f.login(f.assertion(aliceTok, remoteIssuer))
	f.remote.expect(al, 200, "")

	// Block the domain (the admin panel: block list, then revoke-sessions).
	f.remote.expect(f.remote.api("PATCH", "/v1/admin/federation", map[string]any{"block": []string{"home.test"}}, bearer(adm)), 200, "")
	f.remote.expect(f.login(f.assertion(bobTok, remoteIssuer)), 403, "domain_blocked")
	ul := f.remote.api("GET", "/v1/admin/federation/users?domain=home.test", nil, bearer(adm))
	if users := ul.list("users"); len(users) != 2 || users[0]["domain_blocked"] != true || users[0]["sessions"].(float64) < 1 {
		t.Fatalf("users: %s", ul.raw)
	}
	rv := f.remote.api("POST", "/v1/admin/federation/domains/Home.Test/revoke-sessions", nil, bearer(adm))
	f.remote.expect(rv, 200, "")
	if rv.str("domain") != "home.test" || rv.body["revoked"] != float64(2) {
		t.Fatalf("revoke: %s", rv.raw)
	}
	f.remote.expect(f.remote.api("GET", "/v1/me", nil, bearer(bl.str("access_token"))), 401, "")
	f.remote.expect(f.remote.api("GET", "/v1/me", nil, bearer(al.str("access_token"))), 401, "")
	f.remote.expect(f.remote.api("POST", "/v1/admin/federation/domains/not%20a%20domain/revoke-sessions", nil, bearer(adm)), 400, "invalid_request")
	audit := f.remote.api("GET", "/v1/admin/audit?event=federation_domain_sessions_revoked", nil, bearer(adm))
	if !strings.Contains(string(audit.raw), `"revoked":2`) {
		t.Fatalf("audit: %s", audit.raw)
	}
	// Unblock: both sign in again.
	f.remote.expect(f.remote.api("PATCH", "/v1/admin/federation", map[string]any{"block": []string{}}, bearer(adm)), 200, "")
	f.remote.expect(f.login(f.assertion(aliceTok, remoteIssuer)), 200, "")
	bl2 := f.login(f.assertion(bobTok, remoteIssuer))
	f.remote.expect(bl2, 200, "")

	// An admin-disabled account stays disabled through ban + unban.
	f.remote.expect(f.remote.api("POST", "/v1/admin/users/"+aliceID+"/disable", nil, bearer(adm)), 200, "")
	f.remote.expect(f.remote.api("POST", "/v1/admin/federation/users/"+aliceID+"/ban", nil, bearer(adm)), 200, "")
	u := f.remote.api("DELETE", "/v1/admin/federation/users/"+aliceID+"/ban", nil, bearer(adm))
	if u.body["disabled"] != true {
		t.Fatalf("unban re-enabled an admin-disabled account: %s", u.raw)
	}
	f.remote.expect(f.remote.api("POST", "/v1/admin/federation/users/"+bl2.str("user", "id")+"/ban", nil, bearer(bl2.str("access_token"))), 403, "forbidden")
	f.remote.expect(f.remote.api("POST", "/v1/admin/federation/users/"+adminID(f.remote, adm)+"/ban", nil, bearer(adm)), 404, "")

	// Successful sign-ins are audited.
	audit = f.remote.api("GET", "/v1/admin/audit?event=federation_login", nil, bearer(adm))
	if !strings.Contains(string(audit.raw), `"identity":"bob@home.test"`) {
		t.Fatalf("login audit: %s", audit.raw)
	}
}

func adminID(e *env, tok string) string {
	return e.api("GET", "/v1/me", nil, bearer(tok)).str("user", "id")
}

// With the stack config file the settings are its auth.federation keys
// (over env) and read-only through the API.
func TestFederationConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boson.yaml")
	writeConfig(t, path, "version: 1\nauth:\n  federation:\n    mode: allowlist\n    allow: [home.test]\n    remote_voice: false\n")
	f := newFed(t, func(c *config.Config) {
		c.AppConfig.ConfigFile = path
		c.AppConfig.ConfigPoll = 200 * time.Millisecond
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go f.remote.app.StackConfig.Run(ctx)
	adm := f.remote.adminToken("radmin")
	st := f.remote.api("GET", "/v1/admin/federation", nil, bearer(adm))
	f.remote.expect(st, 200, "")
	src := st.body["sources"].(map[string]any)
	if st.str("mode") != "allowlist" || st.body["editable"] != false || src["mode"] != "file" || src["allow"] != "file" ||
		src["block"] != "default" || st.body["remote_voice"] != false || st.str("remote_upload_quota") != "1GB" {
		t.Fatalf("settings: %s", st.raw)
	}
	f.remote.expect(f.remote.api("PATCH", "/v1/admin/federation", map[string]any{"mode": "open"}, bearer(adm)), 409, "settings_managed")
	homeTok := f.homeUser("alice")
	l := f.login(f.assertion(homeTok, remoteIssuer))
	f.remote.expect(l, 200, "")
	f.remote.expect(f.remote.api("POST", "/v1/voice/token", nil, bearer(l.str("access_token"))), 403, "remote_voice_disabled")

	// Live reload: mode off.
	writeConfig(t, path, "version: 1\nauth:\n  federation:\n    mode: \"off\"\n")
	eventually(t, "mode off", func() bool {
		return f.remote.api("GET", "/.well-known/boson-federation.json", nil).str("accepts") == "off"
	})
	f.remote.expect(f.login(f.assertion(homeTok, remoteIssuer)), 403, "federation_off")
	// File gone: back to the database (editable), env defaults.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	eventually(t, "database mode", func() bool {
		return f.remote.api("GET", "/v1/admin/federation", nil, bearer(adm)).body["editable"] == true
	})
}

func TestFederationAssertionChecks(t *testing.T) {
	f := newFed(t, func(c *config.Config) { c.FederationConfig.Mode = config.FederationOpen })
	homeTok := f.homeUser("alice")

	// Replay.
	a := f.assertion(homeTok, remoteIssuer)
	f.remote.expect(f.login(a), 200, "")
	f.remote.expect(f.login(a), 401, "replayed")

	// Wrong audience: an assertion for another server.
	f.remote.expect(f.login(f.assertion(homeTok, "https://auth.other.test")), 401, "bad_assertion")

	// Expired: the remote's clock is 6 minutes ahead.
	a = f.assertion(homeTok, remoteIssuer)
	f.remoteTime.advance(6 * time.Minute)
	f.remote.expect(f.login(a), 401, "bad_assertion")
	f.remoteTime.advance(-6 * time.Minute)

	// Hand-made assertions signed with the home's real key.
	sub := "usr_01JAAAAAAAAAAAAAAAAAAAAAAA"
	ok := f.signAsHome(nil, f.claims(sub, "zed"))
	f.remote.expect(f.login(ok), 200, "")

	bad := map[string]jwt.MapClaims{}
	c := f.claims(sub, "zed")
	c["exp"] = time.Now().Add(30 * time.Minute).Unix() // longer than 5 min
	bad["long lifetime"] = c
	c = f.claims(sub, "zed")
	delete(c, "jti")
	bad["no jti"] = c
	c = f.claims(sub, "zed")
	delete(c, "iat")
	bad["no iat"] = c
	c = f.claims(sub, "zed")
	c["iat"] = time.Now().Add(3 * time.Minute).Unix()
	bad["iat in the future"] = c
	c = f.claims(sub, "zed")
	c["aud"] = remoteIssuer + "/"
	bad["aud not exact"] = c
	c = f.claims(sub, "zed")
	delete(c, "preferred_username")
	bad["no username"] = c
	c = f.claims(sub, "zed")
	c["iss"] = "https://auth.evil.test"
	bad["issuer not in discovery"] = c
	c = f.claims("", "zed")
	bad["no sub"] = c
	for name, claims := range bad {
		r := f.login(f.signAsHome(nil, claims))
		if r.status != 401 || r.str("error") != "bad_assertion" {
			t.Errorf("%s: %d %s", name, r.status, r.raw)
		}
	}
	// Wrong typ (an access token is not an assertion), unsigned junk.
	f.remote.expect(f.login(f.signAsHome(map[string]any{"typ": "at+jwt"}, f.claims(sub, "zed"))), 401, "bad_assertion")
	hl := f.home.login("alice", pw)
	f.remote.expect(f.login(hl.str("access_token")), 401, "bad_assertion")
	f.remote.expect(f.login("not.a.jwt"), 401, "bad_assertion")
	f.remote.expect(f.login(""), 401, "bad_assertion")
	// A signature by a key the home never published.
	forged := f.signAsHome(map[string]any{"kid": "key_unknown"}, f.claims(sub, "zed"))
	f.remote.expect(f.login(forged), 401, "bad_assertion")
	// An assertion from the remote's own issuer.
	f.remote.expect(f.login(f.signAsHome(nil, jwt.MapClaims{"iss": remoteIssuer, "boson_domain": "remote.test"})), 401, "bad_assertion")
}

func TestFederationKeyRotation(t *testing.T) {
	f := newFed(t, func(c *config.Config) { c.FederationConfig.Mode = config.FederationOpen })
	homeTok := f.homeUser("alice")
	f.remote.expect(f.login(f.assertion(homeTok, remoteIssuer)), 200, "") // remote caches the JWKS

	oldKid, _, _ := f.home.app.Keys.SigningKey(t.Context())
	kid, err := f.home.app.Keys.Rotate(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	if kid == oldKid {
		t.Fatal("rotation kept the kid")
	}
	a := f.assertion(homeTok, remoteIssuer)
	tok, _, _ := jwt.NewParser().ParseUnverified(a, jwt.MapClaims{})
	if tok.Header["kid"] != kid {
		t.Fatalf("assertion kid %v, want %s", tok.Header["kid"], kid)
	}
	// Unknown kid: the remote refetches the JWKS (at most every 10 s).
	f.remoteTime.advance(11 * time.Second)
	f.remote.expect(f.login(a), 200, "")
}

func TestFederationHandleClashes(t *testing.T) {
	f := newFed(t, func(c *config.Config) { c.FederationConfig.Mode = config.FederationOpen })
	// Local accounts already called alice, bob and bob-hometest.
	f.remote.registerVerified("alice", "alice@remote.example")
	f.remote.registerVerified("bob", "bob@remote.example")
	f.remote.registerVerified("bob-hometest", "bob2@remote.example")

	a := f.login(f.assertion(f.homeUser("alice"), remoteIssuer))
	f.remote.expect(a, 200, "")
	if a.str("handle") != "alice-hometest" || a.str("identity") != "alice@home.test" {
		t.Fatalf("alice: %s", a.raw)
	}
	b := f.login(f.assertion(f.homeUser("bob"), remoteIssuer))
	f.remote.expect(b, 200, "")
	if b.str("handle") != "bob-hometest2" {
		t.Fatalf("bob: %s", b.raw)
	}
	// A home username that isn't a valid IRC nick is made one.
	c := f.login(f.signAsHome(nil, f.claims("usr_01JBBBBBBBBBBBBBBBBBBBBBBB", "9lives.cat")))
	f.remote.expect(c, 200, "")
	if c.str("handle") != "u9lives_cat" || c.str("identity") != "9lives.cat@home.test" {
		t.Fatalf("odd name: %s", c.raw)
	}
	// The handle is the IRC account name Ergo sees.
	irc := f.remote.do(f.remote.internal, "GET", "/internal/v1/users/alice-hometest/irc", nil, header("X-Internal-Token", f.remote.cfg.InternalConfig.APIToken))
	f.remote.expect(irc, 200, "")
	// The local alice still signs in with her password.
	f.remote.expect(f.remote.login("alice", pw), 200, "")
}

func TestFederationRemoteVoicePolicy(t *testing.T) {
	f := newFed(t, func(c *config.Config) {
		c.FederationConfig.Mode = config.FederationOpen
		c.FederationConfig.RemoteVoice = false
		c.FilesInternalConfig = config.FilesInternalConfig{}
		c.FederationConfig.RemoteRole = ""
	})
	l := f.login(f.assertion(f.homeUser("alice"), remoteIssuer))
	f.remote.expect(l, 200, "")
	f.remote.expect(f.remote.api("POST", "/v1/voice/token", nil, bearer(l.str("access_token"))), 403, "remote_voice_disabled")
	me := f.remote.api("GET", "/v1/me", nil, bearer(l.str("access_token")))
	if rs := me.list("roles"); len(rs) != 0 {
		t.Fatalf("roles without FEDERATION_REMOTE_ROLE: %s", me.raw)
	}
	// Local users keep voice.
	local := f.remote.adminToken("radmin")
	f.remote.expect(f.remote.api("POST", "/v1/voice/token", nil, bearer(local)), 200, "")
	f.remote.expect(f.remote.api("PATCH", "/v1/admin/federation", map[string]any{"remote_voice": true}, bearer(local)), 200, "")
	f.remote.expect(f.remote.api("POST", "/v1/voice/token", nil, bearer(l.str("access_token"))), 200, "")
}

// With ACCOUNT_BACKEND=nickserv federated accounts are local records as
// well, and a NickServ account of the same name never takes one over.
func TestFederationWithNickServBackend(t *testing.T) {
	rpc := newFakeServicesRPC(t, "anope-token")
	f := newFed(t, func(c *config.Config) {
		c.FederationConfig.Mode = config.FederationOpen
		c.AccountsConfig.Backend = config.AccountBackendNickServ
		c.NickServConfig = config.NickServConfig{
			Strategy: config.StrategyAnopeRPC, RPCURL: rpc.srv.URL, RPCToken: "anope-token",
			Timeout: 5 * time.Second, MaxConcurrent: 4, ServiceNick: "NickServ",
			LinkExisting: config.LinkExistingAll, StoreSession: true,
			RateAccountBurst: 1000, RateAccountPerMinute: 1000, RateIPBurst: 1000, RateIPPerMinute: 1000,
			LockoutThreshold: 3, LockoutIPThreshold: 100, LockoutWindow: 15 * time.Minute, LockoutDuration: 15 * time.Minute,
		}
	})
	l := f.login(f.assertion(f.homeUser("alice"), remoteIssuer))
	f.remote.expect(l, 200, "")
	if l.str("handle") != "alice" {
		t.Fatalf("handle: %s", l.raw)
	}
	rpc.add("alice", nsPassword, "alice@irc.example", true)
	f.remote.expect(f.remote.login("alice", nsPassword), 409, "account_name_conflict")
	f.remote.expect(f.login(f.assertion(f.home.login("alice", pw).str("access_token"), remoteIssuer)), 200, "")
}

func TestFederationIdentityLookup(t *testing.T) {
	f := newFed(t, func(c *config.Config) { c.FederationConfig.Mode = config.FederationOpen })
	f.remote.registerVerified("carol", "carol@remote.example")
	f.remote.expect(f.login(f.assertion(f.homeUser("alice"), remoteIssuer)), 200, "")

	r := f.remote.api("GET", "/v1/users/Alice/identity", nil)
	f.remote.expect(r, 200, "")
	if r.str("handle") != "Alice" || r.body["federated"] != true || r.str("identity") != "alice@home.test" || r.str("home_domain") != "home.test" ||
		len(r.body) != 4 || r.header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("alice: %s", r.raw)
	}
	for _, h := range []string{"carol", "nobody"} { // local and unknown look the same
		r = f.remote.api("GET", "/v1/users/"+h+"/identity", nil)
		f.remote.expect(r, 200, "")
		if r.body["federated"] != false || r.body["identity"] != nil || r.body["home_domain"] != nil || len(r.body) != 4 {
			t.Fatalf("%s: %s", h, r.raw)
		}
	}
	b := f.remote.api("POST", "/v1/users/identities", map[string]any{"handles": []string{"alice", "carol", "nobody", "alice"}})
	f.remote.expect(b, 200, "")
	ids := b.body["identities"].(map[string]any)
	if len(ids) != 3 || ids["alice"].(map[string]any)["identity"] != "alice@home.test" || ids["carol"].(map[string]any)["federated"] != false {
		t.Fatalf("batch: %s", b.raw)
	}
	many := make([]string, 201)
	for i := range many {
		many[i] = "u" + randHex(3)
	}
	f.remote.expect(f.remote.api("POST", "/v1/users/identities", map[string]any{"handles": many}), 400, "invalid_request")
}
