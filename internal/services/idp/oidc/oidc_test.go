package oidc

import "testing"

func TestNormalize(t *testing.T) {
	k := Kind{}
	out, err := k.Normalize(map[string]any{"issuer": " https://accounts.google.com ", "client_id": "abc", "scopes": []any{"email"}})
	if err != nil {
		t.Fatal(err)
	}
	if out["issuer"] != "https://accounts.google.com" || len(out["scopes"].([]any)) != 2 || out["scopes"].([]any)[0] != "openid" {
		t.Fatalf("normalized: %v", out)
	}
	if out, _ := k.Normalize(map[string]any{"issuer": "http://127.0.0.1:5556/dex", "client_id": "a"}); out == nil {
		t.Error("loopback http issuer rejected")
	}
	for _, bad := range []map[string]any{
		{"client_id": "a"},
		{"issuer": "https://x"},
		{"issuer": "http://idp.example.com", "client_id": "a"},
		{"issuer": "https://x?y=1", "client_id": "a"},
		{"issuer": "https://x", "client_id": "a", "client_secret_env": "X"},
		{"issuer": "https://x", "client_id": "a", "scopes": []any{"two words"}},
	} {
		if _, err := k.Normalize(bad); err == nil {
			t.Errorf("Normalize(%v) accepted", bad)
		}
	}
	if _, err := (Kind{AllowHTTP: true}).Normalize(map[string]any{"issuer": "http://keycloak:8080/realms/boson", "client_id": "a"}); err != nil {
		t.Errorf("AllowHTTP: %v", err)
	}
}

func TestIdentityFromClaims(t *testing.T) {
	p := &Provider{cfg: Config{UsernameClaim: "login"}}
	x := p.identityFrom("sub1", map[string]any{"email": " A@B.c ", "email_verified": "true", "name": "Al", "preferred_username": "al", "login": "al2"})
	if x.Subject != "sub1" || x.Email != "A@B.c" || !x.EmailVerified || x.DisplayName != "Al" || x.PreferredUsername != "al2" {
		t.Fatalf("%+v", x)
	}
	x = (&Provider{}).identityFrom("s", map[string]any{"nickname": "nick", "email_verified": false})
	if x.PreferredUsername != "nick" || x.EmailVerified {
		t.Fatalf("%+v", x)
	}
}
