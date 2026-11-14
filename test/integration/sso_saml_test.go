package integration

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	nethttp "net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/crewjam/saml/samlidp"
)

// testSAMLIdP runs crewjam's samlidp (a complete SAML IdP with a login
// form) in-process, with one user.
type testSAMLIdP struct {
	srv *httptest.Server
}

func newSAMLIdP(t *testing.T) *testSAMLIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	var h nethttp.Handler
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	s, err := samlidp.New(samlidp.Options{URL: *u, Key: key, Certificate: cert, Store: &samlidp.MemoryStore{}})
	if err != nil {
		t.Fatal(err)
	}
	h = s
	idp := &testSAMLIdP{srv: srv}
	b, _ := json.Marshal(map[string]any{"name": "carol", "password": "carol-password", "email": "carol@corp.example", "common_name": "Carol Danvers"})
	idp.put(t, "/users/carol", b)
	return idp
}

func (i *testSAMLIdP) put(t *testing.T, path string, body []byte) {
	t.Helper()
	req, _ := nethttp.NewRequest("PUT", i.srv.URL+path, bytes.NewReader(body))
	res, err := nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode >= 300 {
		t.Fatalf("PUT %s: %d %s", path, res.StatusCode, b)
	}
}

// samlProvider creates the provider, then registers our SP metadata at the IdP.
func (e *env) samlProvider(adminAT, slug string, idp *testSAMLIdP) map[string]any {
	e.t.Helper()
	r := e.api("POST", "/v1/admin/sso/providers", map[string]any{
		"slug": slug, "kind": "saml", "display_name": "Corp SAML", "enabled": true, "allow_signup": true, "trust_email": true,
		"config": map[string]any{"idp_metadata_url": idp.srv.URL + "/metadata"},
	}, bearer(adminAT))
	e.expect(r, 201, "")
	p := r.body["provider"].(map[string]any)
	md, body := e.get(e.browser(), e.local(p["sp_metadata_url"].(string)))
	if md.StatusCode != 200 || md.Header.Get("Content-Type") != "application/samlmetadata+xml" {
		e.t.Fatalf("SP metadata: %d %s", md.StatusCode, body)
	}
	idp.put(e.t, "/services/"+slug, []byte(body))
	return p
}

// samlToACS runs start → IdP (logging in if needed) and returns the ACS
// form the IdP auto-posts.
func (e *env) samlToACS(slug string, query url.Values) (string, url.Values) {
	e.t.Helper()
	c := e.browser()
	res, body := e.get(c, e.public.URL+"/v1/sso/"+slug+"/start?"+query.Encode())
	sso := location(e.t, res, body)
	if sso.Query().Get("SAMLRequest") == "" || sso.Query().Get("RelayState") == "" {
		e.t.Fatalf("not a SAML redirect: %s", sso)
	}
	res, body = e.get(c, sso.String())
	if strings.Contains(body, `name="password"`) {
		action, form := parseForm(e.t, body)
		form.Set("user", "carol")
		form.Set("password", "carol-password")
		res, body = e.postForm(c, action, form)
	}
	if res.StatusCode != 200 || !strings.Contains(body, "SAMLResponse") {
		e.t.Fatalf("IdP did not answer with a response form: %d %s", res.StatusCode, body)
	}
	return parseForm(e.t, body)
}

func TestSAMLLoginAgainstTestIdP(t *testing.T) {
	e := newEnv(t)
	adminAT := e.adminToken("samladmin")
	idp := newSAMLIdP(t)
	p := e.samlProvider(adminAT, "corp", idp)
	base := e.cfg.HTTPConfig.PublicURL + "/v1/sso/corp"
	if p["acs_url"] != base+"/saml/acs" || p["sp_metadata_url"] != base+"/saml/metadata" || p["sp_entity_id"] != base+"/saml/metadata" ||
		!strings.Contains(p["sp_certificate"].(string), "BEGIN CERTIFICATE") || p["config"].(map[string]any)["has_client_secret"] != nil {
		t.Fatalf("saml provider: %v", p)
	}
	tr := e.api("POST", "/v1/admin/sso/providers/"+p["id"].(string)+"/test", nil, bearer(adminAT))
	if tr.body["ok"] != true || tr.body["details"].(map[string]any)["signing_certificates"].(float64) < 1 {
		t.Fatalf("test: %s", tr.raw)
	}

	// Cookie mode sign-up.
	action, form := e.samlToACS("corp", url.Values{"return_to": {"/chat"}})
	if action != base+"/saml/acs" {
		t.Fatalf("ACS action %s", action)
	}
	res, body := e.postForm(e.browser(), e.local(action), form)
	if loc := location(t, res, body); loc.String() != "https://app.integration.test/chat" {
		t.Fatalf("ACS redirect: %s", loc)
	}
	var at string
	for _, c := range res.Cookies() {
		if c.Name == "boson_at" {
			at = c.Value
		}
	}
	me := e.api("GET", "/v1/me", nil, bearer(at))
	e.expect(me, 200, "")
	u := me.body["user"].(map[string]any)
	if u["username"] != "carol" || u["email"] != "carol@corp.example" || u["email_verified"] != true || u["display_name"] != "Carol Danvers" {
		t.Fatalf("saml user: %s", me.raw)
	}
	ids := e.api("GET", "/v1/me/identities", nil, bearer(at)).list("identities")
	if len(ids) != 1 || ids[0]["provider_kind"] != "saml" || ids[0]["subject"] != "carol@corp.example" {
		t.Fatalf("identities: %v", ids)
	}

	// Replaying the same response: its state cookie is gone.
	res, body = e.postForm(e.browser(), e.local(action), form)
	if res.StatusCode != 400 || !strings.Contains(body, "invalid_state") {
		t.Fatalf("replay: %d %s", res.StatusCode, body)
	}

	// Code mode, same account (the IdP already has a session).
	action, form = e.samlToACS("corp", url.Values{"return_to": {"boson://sso"}})
	res, body = e.postForm(e.browser(), e.local(action), form)
	loc := location(t, res, body)
	x := e.api("POST", "/v1/sso/exchange", map[string]string{"code": loc.Query().Get("code")})
	e.expect(x, 200, "")
	if x.str("user", "id") != u["id"] {
		t.Fatalf("code-mode SAML login reached another account: %s", x.raw)
	}

	// Tampering is caught: the assertion is encrypted to our SP key and the
	// response signed by the IdP, so changing the ciphertext fails. (Dropping
	// only the outer signature is fine per spec: samlidp also signs the
	// assertion inside the encryption.)
	sigRE := regexp.MustCompile(`(?s)<ds:Signature.*?</ds:Signature>`)
	cipherRE := regexp.MustCompile(`<xenc:CipherValue>(.)`)
	for name, tamper := range map[string]func([]byte) []byte{
		"ciphertext": func(b []byte) []byte {
			return cipherRE.ReplaceAllFunc(b, func(m []byte) []byte {
				if m[len(m)-1] == 'A' {
					return append(m[:len(m)-1], 'B')
				}
				return append(m[:len(m)-1], 'A')
			})
		},
	} {
		action, form = e.samlToACS("corp", url.Values{"return_to": {"/x"}})
		raw, _ := base64.StdEncoding.DecodeString(form.Get("SAMLResponse"))
		if !bytes.Contains(raw, []byte("EncryptedAssertion")) || !sigRE.Match(raw) {
			t.Fatalf("expected a signed response with an encrypted assertion: %.300s", raw)
		}
		changed := tamper(bytes.Clone(raw))
		if bytes.Equal(changed, raw) {
			t.Fatalf("%s: tamper changed nothing", name)
		}
		form.Set("SAMLResponse", base64.StdEncoding.EncodeToString(changed))
		res, body = e.postForm(e.browser(), e.local(action), form)
		if loc := location(t, res, body); loc.Query().Get("error") != "sso_failed" {
			t.Fatalf("%s tamper accepted: %s", name, loc)
		}
	}

	// The response is bound to our request: a response for a request made in
	// another browser (state cookie) is refused.
	action, form = e.samlToACS("corp", url.Values{})
	stranger := &nethttp.Client{CheckRedirect: e.browser().CheckRedirect}
	res, body = e.postForm(stranger, e.local(action), form)
	if res.StatusCode != 400 || !strings.Contains(body, "invalid_state") {
		t.Fatalf("cross-browser: %d %s", res.StatusCode, body)
	}

	// Metadata of unknown / non-SAML providers.
	e.expect(e.api("GET", "/v1/sso/nope/saml/metadata", nil), 404, "unknown_provider")
}

func TestSAMLStateCookieIsSameSiteNoneWhenSecure(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.HTTPConfig.CookieSecure = true })
	adminAT := e.adminToken("samladmin")
	idp := newSAMLIdP(t)
	e.samlProvider(adminAT, "corp", idp)
	res, _ := e.get(e.browser(), e.public.URL+"/v1/sso/corp/start")
	sc := strings.Join(res.Header.Values("Set-Cookie"), "\n")
	if !strings.Contains(sc, "boson_sso=") || !strings.Contains(sc, "SameSite=None") || !strings.Contains(sc, "Secure") || !strings.Contains(sc, "HttpOnly") {
		t.Fatalf("state cookie: %s", sc)
	}
}

func TestSAMLProviderWithInlineMetadata(t *testing.T) {
	e := newEnv(t)
	adminAT := e.adminToken("samladmin")
	idp := newSAMLIdP(t)
	_, xml := e.get(e.browser(), idp.srv.URL+"/metadata")
	r := e.api("POST", "/v1/admin/sso/providers", map[string]any{
		"slug": "okta", "kind": "saml", "enabled": true,
		"config": map[string]any{"idp_metadata_xml": xml, "entity_id": "urn:boson:sp", "name_id_format": "email",
			"attribute_map": map[string]any{"email": "mail", "username": "uid", "display_name": "cn"}},
	}, bearer(adminAT))
	e.expect(r, 201, "")
	p := r.body["provider"].(map[string]any)
	if p["sp_entity_id"] != "urn:boson:sp" || p["display_name"] != "okta" {
		t.Fatalf("provider: %s", r.raw)
	}
	_, md := e.get(e.browser(), e.local(p["sp_metadata_url"].(string)))
	if !strings.Contains(md, `entityID="urn:boson:sp"`) {
		t.Fatalf("entity id not in metadata: %s", md)
	}
	e.expect(e.api("PATCH", "/v1/admin/sso/providers/"+p["id"].(string), map[string]any{"config": map[string]any{"name_id_format": "transient"}}, bearer(adminAT)), 400, "invalid_request")
	tr := e.api("POST", "/v1/admin/sso/providers/"+p["id"].(string)+"/test", nil, bearer(adminAT))
	if tr.body["ok"] != true {
		t.Fatalf("test: %s", tr.raw)
	}
}
