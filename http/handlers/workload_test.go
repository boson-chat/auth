package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories/signingkey/signingkeytest"
	"github.com/boson-chat/auth/internal/services/workload"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2/google/externalaccount"
)

const testWorkloadSecret = "0123456789abcdef0123456789abcdef"

// workloadServers runs the public and internal routes of h (Workload set or nil).
func workloadServers(t *testing.T, on bool) (*Handlers, *httptest.Server, *httptest.Server) {
	t.Helper()
	h := &Handlers{}
	if on {
		kek := make([]byte, 32)
		_, _ = rand.Read(kek)
		ks, err := workload.NewKeySet(signingkeytest.New(), db.NoTx{}, workload.KeyOptions{
			EncryptionKey: kek, Rotation: 720 * time.Hour, PublishLead: time.Hour, TokenTTL: 5 * time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := ks.Ensure(context.Background()); err != nil {
			t.Fatal(err)
		}
		h.Workload = workload.NewService(ks, "https://auth.example.com", 5*time.Minute, []config.WorkloadIdentity{
			{Name: "pushrelay", Audiences: []string{"boson-pushrelay"}, Token: testWorkloadSecret},
		}, nil)
	}
	pub, internal := nethttp.NewServeMux(), nethttp.NewServeMux()
	h.registerWorkloadPublic(pub)
	h.registerWorkloadInternal(internal)
	ps, is := httptest.NewServer(pub), httptest.NewServer(internal)
	t.Cleanup(func() { ps.Close(); is.Close() })
	return h, ps, is
}

func wget(t *testing.T, url string, hdr ...string) (*nethttp.Response, []byte) {
	t.Helper()
	req, _ := nethttp.NewRequest("GET", url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := nethttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

func TestWorkloadOffIs404(t *testing.T) {
	_, pub, internal := workloadServers(t, false)
	for _, u := range []string{pub.URL + "/workload/.well-known/openid-configuration", pub.URL + "/workload/jwks.json",
		internal.URL + "/internal/v1/workload/token"} {
		if res, _ := wget(t, u, WorkloadTokenHeader, testWorkloadSecret); res.StatusCode != 404 {
			t.Errorf("%s: %d", u, res.StatusCode)
		}
	}
}

func TestWorkloadDiscoveryAndJWKS(t *testing.T) {
	_, pub, _ := workloadServers(t, true)
	res, body := wget(t, pub.URL+"/workload/.well-known/openid-configuration")
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil || res.StatusCode != 200 {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	if doc["issuer"] != "https://auth.example.com/workload" || doc["jwks_uri"] != "https://auth.example.com/workload/jwks.json" {
		t.Fatalf("discovery %v", doc)
	}
	if algs, _ := doc["id_token_signing_alg_values_supported"].([]any); len(algs) != 1 || algs[0] != "ES256" {
		t.Fatalf("algs %v", doc["id_token_signing_alg_values_supported"])
	}
	res, body = wget(t, pub.URL+"/workload/jwks.json")
	var set workload.JWKS
	if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) != 1 || set.Keys[0].Kty != "EC" || set.Keys[0].Alg != "ES256" {
		t.Fatalf("jwks %s", body)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/jwk-set+json" {
		t.Fatalf("content type %q", ct)
	}
	// The token endpoint is not on the public listener.
	if res, _ := wget(t, pub.URL+"/internal/v1/workload/token", WorkloadTokenHeader, testWorkloadSecret); res.StatusCode != 404 {
		t.Fatalf("public token endpoint: %d", res.StatusCode)
	}
}

func TestWorkloadTokenEndpoint(t *testing.T) {
	_, _, internal := workloadServers(t, true)
	u := internal.URL + "/internal/v1/workload/token"
	for name, c := range map[string]struct {
		url, secret string
		status      int
	}{
		"no secret":           {u, "", 401},
		"wrong secret":        {u, "nope", 401},
		"internal api header": {u, "", 401},
		"other audience":      {u + "?audience=boson", testWorkloadSecret, 403},
		"bad format":          {u + "?format=xml", testWorkloadSecret, 400},
	} {
		res, body := wget(t, c.url, WorkloadTokenHeader, c.secret, InternalTokenHeader, testWorkloadSecret)
		if res.StatusCode != c.status {
			t.Errorf("%s: %d %s", name, res.StatusCode, body)
		}
	}

	res, body := wget(t, u+"?audience=boson-pushrelay", WorkloadTokenHeader, testWorkloadSecret)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil || res.StatusCode != 200 {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	if res.Header.Get("Cache-Control") != "no-store" || out["expires_in"] != float64(300) || out["token_type"] == "" {
		t.Fatalf("response %v %v", res.Header, out)
	}
	if s, _ := out["id_token"].(string); strings.Count(s, ".") != 2 {
		t.Fatalf("id_token %v", out["id_token"])
	}

	res, body = wget(t, u+"?format=text", WorkloadTokenHeader, testWorkloadSecret)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/jwt" || strings.Count(string(body), ".") != 2 {
		t.Fatalf("text: %d %q %s", res.StatusCode, res.Header.Get("Content-Type"), body)
	}
}

// Google's own client (external_account, url credential source) gets the
// token from the internal endpoint and hands it to STS; a fake STS checks
// it the way Workload Identity Federation does (discovery → JWKS → ES256,
// iss, aud, sub, exp ≤ 24 h after iat), then a fake IAM Credentials
// impersonates the service account.
func TestWorkloadTokenWithGoogleExternalAccount(t *testing.T) {
	h, pub, internal := workloadServers(t, true)
	const provider = "//iam.googleapis.com/projects/732970671821/locations/global/workloadIdentityPools/boson/providers/auth-boson-chat"
	var gotSub string
	sts := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_ = r.ParseForm()
		if r.Form.Get("audience") != provider || r.Form.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:jwt" {
			nethttp.Error(w, "bad request "+r.Form.Encode(), 400)
			return
		}
		_, body := wget(t, pub.URL+"/workload/jwks.json")
		var set workload.JWKS
		_ = json.Unmarshal(body, &set)
		var claims jwt.RegisteredClaims
		_, err := jwt.ParseWithClaims(r.Form.Get("subject_token"), &claims, func(tk *jwt.Token) (any, error) {
			for _, k := range set.Keys {
				if k.Kid == tk.Header["kid"] {
					x, _ := base64.RawURLEncoding.DecodeString(k.X)
					y, _ := base64.RawURLEncoding.DecodeString(k.Y)
					return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
				}
			}
			return nil, jwt.ErrTokenUnverifiable
		}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(h.Workload.Issuer()), jwt.WithAudience("boson-pushrelay"),
			jwt.WithIssuedAt(), jwt.WithExpirationRequired())
		if err != nil || claims.ExpiresAt.Sub(claims.IssuedAt.Time) > 24*time.Hour {
			nethttp.Error(w, "invalid subject token", 400)
			return
		}
		gotSub = claims.Subject
		writeJSON(w, 200, map[string]any{"access_token": "federated", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type": "Bearer", "expires_in": 3600})
	}))
	defer sts.Close()
	iam := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.Header.Get("Authorization") != "Bearer federated" {
			nethttp.Error(w, "unauthenticated", 401)
			return
		}
		writeJSON(w, 200, map[string]any{"accessToken": "sa-token", "expireTime": time.Now().Add(time.Hour).Format(time.RFC3339)})
	}))
	defer iam.Close()

	ts, err := externalaccount.NewTokenSource(context.Background(), externalaccount.Config{
		Audience:                       provider,
		SubjectTokenType:               "urn:ietf:params:oauth:token-type:jwt",
		TokenURL:                       sts.URL + "/v1/token",
		ServiceAccountImpersonationURL: iam.URL + "/v1/projects/-/serviceAccounts/pushrelay@boson-f7443.iam.gserviceaccount.com:generateAccessToken",
		Scopes:                         []string{"https://www.googleapis.com/auth/firebase.messaging"},
		CredentialSource: &externalaccount.CredentialSource{
			URL:     internal.URL + "/internal/v1/workload/token",
			Headers: map[string]string{WorkloadTokenHeader: testWorkloadSecret},
			Format:  externalaccount.Format{Type: "json", SubjectTokenFieldName: WorkloadTokenField},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := ts.Token()
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "sa-token" || gotSub != "service:pushrelay" {
		t.Fatalf("token %q sub %q", tok.AccessToken, gotSub)
	}
}
