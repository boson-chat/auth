package integration

import (
	"context"
	"sync"
	"testing"

	authhttp "github.com/boson-chat/auth/http"
)

// Two concurrent refreshes with the same token: at most one wins, and the
// loser is treated as reuse, which then revokes the session.
func TestConcurrentRefreshSameToken(t *testing.T) {
	e := newEnv(t)
	e.registerVerified("sam", "sam@example.com")
	rt := e.login("sam", pw).str("refresh_token")

	const n = 8
	statuses := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			statuses[i] = e.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": rt}).status
		})
	}
	wg.Wait()
	ok := 0
	for _, s := range statuses {
		switch s {
		case 200:
			ok++
		case 401:
		default:
			t.Fatalf("unexpected status %d", s)
		}
	}
	if ok > 1 {
		t.Fatalf("%d concurrent refreshes succeeded with one token", ok)
	}
	sessions, err := e.app.Sessions.ListActive(t.Context(), e.login("sam", pw).body["user"].(map[string]any)["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 { // only the session from the login just above
		t.Fatalf("reuse should have revoked the raced session; active = %d", len(sessions))
	}
}

// Replicas starting together create exactly one signing key.
func TestReplicasCreateOneKey(t *testing.T) {
	e := newEnv(t)
	// newEnv already ran Ensure once; wipe and race several fresh replicas.
	if err := e.app.DB.DB.Exec("DELETE FROM signing_keys").Error; err != nil {
		t.Fatal(err)
	}
	const replicas = 5
	apps := make([]*authhttp.App, replicas)
	for i := range apps {
		a, err := authhttp.Build(context.Background(), e.cfg, authhttp.Options{Mailer: e.mail})
		if err != nil {
			t.Fatal(err)
		}
		apps[i] = a
		t.Cleanup(func() { _ = a.Close() })
	}
	var wg sync.WaitGroup
	errs := make([]error, replicas)
	for i, a := range apps {
		wg.Go(func() { errs[i] = a.Keys.Ensure(context.Background()) })
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int64
	if err := e.app.DB.DB.Raw("SELECT count(*) FROM signing_keys").Scan(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("%d replicas created %d keys, want 1", replicas, count)
	}
	kid0, _, _ := apps[0].Keys.SigningKey(context.Background())
	for _, a := range apps[1:] {
		if kid, _, _ := a.Keys.SigningKey(context.Background()); kid != kid0 {
			t.Fatalf("replicas disagree on signing key: %s vs %s", kid, kid0)
		}
	}
}
