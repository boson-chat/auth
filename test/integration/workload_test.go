package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"testing"

	"github.com/boson-chat/auth/config"
)

const workloadSecret = "wl-0123456789abcdef0123456789abcdef"

func withWorkload(c *config.Config) {
	c.WorkloadConfig.Identities = "pushrelay:boson-pushrelay"
	c.WorkloadConfig.Getenv = func(k string) string {
		if k == "WORKLOAD_TOKEN_PUSHRELAY" {
			return workloadSecret
		}
		return ""
	}
}

// The workload issuer end to end on Postgres: its ES256 key lives in
// workload_signing_keys, never in the main JWKS, and the internal endpoint
// mints a token the workload JWKS verifies.
func TestWorkloadIssuer(t *testing.T) {
	e := newEnv(t, withWorkload)
	ctx := context.Background()
	if e.app.Workload == nil {
		t.Fatal("workload issuer off")
	}
	if err := e.app.Workload.Keys.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	// Another replica's Ensure creates nothing new.
	if err := e.app.Workload.Keys.Ensure(ctx); err != nil {
		t.Fatal(err)
	}

	d := e.api("GET", "/workload/.well-known/openid-configuration", nil)
	e.expect(d, 200, "")
	if d.str("issuer") != issuer+"/workload" || d.str("jwks_uri") != issuer+"/workload/jwks.json" {
		t.Fatalf("discovery %s", d.raw)
	}
	j := e.api("GET", "/workload/jwks.json", nil)
	var set struct {
		Keys []struct{ Kid, Kty, Crv, Alg string } `json:"keys"`
	}
	if err := json.Unmarshal(j.raw, &set); err != nil || len(set.Keys) != 1 || set.Keys[0].Alg != "ES256" || set.Keys[0].Crv != "P-256" {
		t.Fatalf("workload jwks %s", j.raw)
	}
	wkid := set.Keys[0].Kid

	main := e.api("GET", "/.well-known/jwks.json", nil)
	var mainSet struct {
		Keys []struct{ Kid, Alg string } `json:"keys"`
	}
	_ = json.Unmarshal(main.raw, &mainSet)
	if len(mainSet.Keys) == 0 || slices.ContainsFunc(mainSet.Keys, func(k struct{ Kid, Alg string }) bool { return k.Kid == wkid || k.Alg != "EdDSA" }) {
		t.Fatalf("main JWKS has workload keys: %s", main.raw)
	}

	r := e.do(e.internal, "GET", "/internal/v1/workload/token?audience=boson-pushrelay", nil, header("X-Workload-Token", workloadSecret))
	e.expect(r, 200, "")
	if r.str("id_token") == "" {
		t.Fatalf("token %s", r.raw)
	}
	// INTERNAL_API_TOKEN is not a workload secret.
	e.expect(e.do(e.internal, "GET", "/internal/v1/workload/token", nil,
		header("X-Workload-Token", e.cfg.InternalConfig.APIToken), header("X-Internal-Token", e.cfg.InternalConfig.APIToken)), 401, "")

	sqldb, err := sql.Open("pgx", e.cfg.DBConfig.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer sqldb.Close()
	var n, m int
	_ = sqldb.QueryRow(`SELECT count(*) FROM workload_signing_keys WHERE alg = 'ES256'`).Scan(&n)
	_ = sqldb.QueryRow(`SELECT count(*) FROM signing_keys WHERE kid = $1`, wkid).Scan(&m)
	if n != 1 || m != 0 {
		t.Fatalf("workload keys %d, in signing_keys %d", n, m)
	}
}

func TestWorkloadIssuerOff(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/workload/.well-known/openid-configuration", "/workload/jwks.json"} {
		e.expect(e.api("GET", p, nil), 404, "")
	}
	e.expect(e.do(e.internal, "GET", "/internal/v1/workload/token", nil, header("X-Workload-Token", workloadSecret)), 404, "")
}
