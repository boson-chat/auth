package integration

import (
	"testing"
	"time"
)

// GET /internal/v1/stats counts accounts and those active in the last 7
// and 30 days; it needs INTERNAL_API_TOKEN like the rest of /internal/v1.
func TestInternalStats(t *testing.T) {
	e := newEnv(t)
	e.adminToken("boss") // active now (signed in)
	week := e.registerVerified("weekly", "weekly@example.com")
	month := e.registerVerified("monthly", "monthly@example.com")
	old := e.registerVerified("old", "old@example.com")
	e.registerVerified("never", "never@example.com")

	sqldb := e.sqlDB()
	now := time.Now()
	for id, at := range map[string]time.Time{
		week:  now.Add(-6 * 24 * time.Hour),
		month: now.Add(-20 * 24 * time.Hour),
		old:   now.Add(-45 * 24 * time.Hour),
	} {
		if _, err := sqldb.Exec(`UPDATE users SET last_active_at = $1 WHERE id = $2`, at, id); err != nil {
			t.Fatal(err)
		}
	}

	r := e.internalAPI("GET", "/internal/v1/stats", nil)
	e.expect(r, 200, "")
	for k, want := range map[string]float64{"accounts": 5, "active_7d": 2, "active_30d": 3} {
		if got, _ := r.body[k].(float64); got != want {
			t.Errorf("%s = %v, want %v (%s)", k, r.body[k], want, r.raw)
		}
	}
	if len(r.body) != 3 {
		t.Errorf("unexpected fields: %s", r.raw)
	}

	e.expect(e.do(e.internal, "GET", "/internal/v1/stats", nil), 401, "")
	e.expect(e.do(e.internal, "GET", "/internal/v1/stats", nil, header("X-Internal-Token", "wrong")), 401, "")
	// Not on the public listener.
	if r := e.api("GET", "/internal/v1/stats", nil, header("X-Internal-Token", e.cfg.InternalConfig.APIToken)); r.status == 200 {
		t.Fatalf("public listener served stats: %s", r.raw)
	}
}
