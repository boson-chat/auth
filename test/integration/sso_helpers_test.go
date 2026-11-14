package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"html"
	"io"
	nethttp "net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/oauth2-proxy/mockoidc"
)

// browser follows no redirects on its own so tests can inspect each hop.
// It shares the env's cookie jar.
func (e *env) browser() *nethttp.Client {
	return &nethttp.Client{Jar: e.client.Jar, CheckRedirect: func(*nethttp.Request, []*nethttp.Request) error {
		return nethttp.ErrUseLastResponse
	}}
}

// local rewrites a URL on PUBLIC_URL (what auth puts in redirects and
// metadata) to the test server.
func (e *env) local(raw string) string {
	return strings.Replace(raw, e.cfg.HTTPConfig.PublicURL, e.public.URL, 1)
}

func (e *env) get(c *nethttp.Client, raw string) (*nethttp.Response, string) {
	e.t.Helper()
	res, err := c.Get(raw)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func (e *env) postForm(c *nethttp.Client, raw string, form url.Values) (*nethttp.Response, string) {
	e.t.Helper()
	res, err := c.PostForm(raw, form)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func location(t *testing.T, res *nethttp.Response, body string) *url.URL {
	t.Helper()
	if res.StatusCode != 302 && res.StatusCode != 303 {
		t.Fatalf("expected a redirect, got %d: %s", res.StatusCode, body)
	}
	u, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

var (
	formActionRE = regexp.MustCompile(`<form[^>]*action="([^"]*)"`)
	inputRE      = regexp.MustCompile(`<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"`)
)

// parseForm extracts the action and hidden inputs of the first HTML form.
func parseForm(t *testing.T, body string) (string, url.Values) {
	t.Helper()
	m := formActionRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no form in: %s", body)
	}
	v := url.Values{}
	for _, in := range inputRE.FindAllStringSubmatch(body, -1) {
		v.Set(html.UnescapeString(in[1]), html.UnescapeString(in[2]))
	}
	return html.UnescapeString(m[1]), v
}

func pkce(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// mockIdP is a real OIDC provider (discovery, JWKS, authorize, token,
// userinfo) running in-process.
func mockIdP(t *testing.T) *mockoidc.MockOIDC {
	t.Helper()
	m, err := mockoidc.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Shutdown() })
	return m
}

// oidcProvider registers the mock IdP through the admin API.
func (e *env) oidcProvider(adminAT, slug string, m *mockoidc.MockOIDC, fields map[string]any) string {
	e.t.Helper()
	body := map[string]any{
		"slug": slug, "kind": "oidc", "display_name": "Mock " + slug, "enabled": true, "allow_signup": true,
		"config": map[string]any{"issuer": m.Issuer(), "client_id": m.ClientID, "client_secret": m.ClientSecret},
	}
	for k, v := range fields {
		body[k] = v
	}
	r := e.api("POST", "/v1/admin/sso/providers", body, bearer(adminAT))
	e.expect(r, 201, "")
	return r.str("provider", "id")
}

// oidcLogin runs start → IdP → callback as a browser and returns the final
// response (the redirect to return_to). user is queued at the IdP first.
func (e *env) oidcLogin(slug string, m *mockoidc.MockOIDC, user *mockoidc.MockUser, query url.Values) *nethttp.Response {
	e.t.Helper()
	c := e.browser()
	if user != nil {
		m.QueueUser(user)
	}
	res, body := e.get(c, e.public.URL+"/v1/sso/"+slug+"/start?"+query.Encode())
	authz := location(e.t, res, body)
	if !strings.HasPrefix(authz.String(), m.Issuer()) {
		e.t.Fatalf("start redirected to %s, not the IdP", authz)
	}
	q := authz.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
		e.t.Fatalf("authorize request lacks PKCE/nonce/state: %s", authz)
	}
	res, body = e.get(c, authz.String())
	cb := location(e.t, res, body)
	res, err := c.Get(e.local(cb.String()))
	if err != nil {
		e.t.Fatal(err)
	}
	res.Body.Close()
	return res
}
