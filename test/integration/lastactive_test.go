package integration

import (
	"database/sql"
	"testing"
	"time"

	"github.com/boson-chat/auth/db"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/services/session"
)

// adminUser returns GET /v1/admin/users/{id}'s user object.
func (e *env) adminUser(adminAT, id string) map[string]any {
	e.t.Helper()
	r := e.api("GET", "/v1/admin/users/"+id, nil, bearer(adminAT))
	e.expect(r, 200, "")
	return r.body["user"].(map[string]any)
}

func (e *env) sqlDB() *sql.DB {
	e.t.Helper()
	sqldb, err := sql.Open("pgx", e.cfg.DBConfig.URL)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = sqldb.Close() })
	return sqldb
}

func ts(t *testing.T, v any) time.Time {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("timestamp = %v", v)
	}
	at, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// The admin user list and detail carry last sign-in (time, method, ip) and
// last activity; null until the user signs in.
func TestAdminUserLastSignInAndActive(t *testing.T) {
	e := newEnv(t)
	adminAT := e.adminToken("boss")
	uid := e.registerVerified("carol", "carol@example.com")
	quiet := e.registerVerified("quiet", "quiet@example.com")

	never := e.adminUser(adminAT, quiet)
	for _, k := range []string{"last_sign_in_at", "last_sign_in_method", "last_sign_in_ip", "last_active_at"} {
		if v, ok := never[k]; !ok || v != nil {
			t.Fatalf("%s = %v (present %v), want null", k, v, ok)
		}
	}

	before := time.Now().Add(-time.Second)
	login := e.login("carol", pw)
	e.expect(login, 200, "")
	u := e.adminUser(adminAT, uid)
	signIn := ts(t, u["last_sign_in_at"])
	if signIn.Before(before) || u["last_sign_in_method"] != "password" || u["last_sign_in_ip"] == "" {
		t.Fatalf("after login: %v", u)
	}
	if !ts(t, u["last_active_at"]).Equal(signIn) {
		t.Fatalf("last_active_at %v != sign-in %v", u["last_active_at"], signIn)
	}

	// Refresh within the throttle interval: activity unchanged.
	r := e.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": login.str("refresh_token")})
	e.expect(r, 200, "")
	if got := ts(t, e.adminUser(adminAT, uid)["last_active_at"]); !got.Equal(signIn) {
		t.Fatalf("throttled refresh moved last_active_at to %v", got)
	}

	// Stored value older than the interval: the next refresh writes it.
	sqldb := e.sqlDB()
	old := time.Now().Add(-session.ActivityInterval - time.Minute)
	if _, err := sqldb.Exec(`UPDATE users SET last_active_at = $1 WHERE id = $2`, old, uid); err != nil {
		t.Fatal(err)
	}
	r = e.api("POST", "/v1/token/refresh", map[string]string{"refresh_token": r.str("refresh_token")})
	e.expect(r, 200, "")
	u = e.adminUser(adminAT, uid)
	if got := ts(t, u["last_active_at"]); !got.After(old.Add(session.ActivityInterval)) {
		t.Fatalf("refresh after interval: last_active_at = %v", got)
	}
	if !ts(t, u["last_sign_in_at"]).Equal(signIn) {
		t.Fatal("a refresh is not a sign-in")
	}

	// List: same fields, sortable.
	list := e.api("GET", "/v1/admin/users?sort=last_active", nil, bearer(adminAT))
	e.expect(list, 200, "")
	users := list.list("users")
	if len(users) != 3 || users[0]["id"] != uid || users[2]["id"] != quiet {
		t.Fatalf("sort=last_active order: %s", list.raw)
	}
	if users[0]["last_sign_in_method"] != "password" || users[2]["last_active_at"] != nil {
		t.Fatalf("list fields: %s", list.raw)
	}
	list = e.api("GET", "/v1/admin/users?sort=last_sign_in&limit=1&offset=2", nil, bearer(adminAT))
	e.expect(list, 200, "")
	if got := list.list("users"); len(got) != 1 || got[0]["id"] != quiet || list.body["total"].(float64) != 3 {
		t.Fatalf("sort=last_sign_in paging: %s", list.raw)
	}
	e.expect(e.api("GET", "/v1/admin/users?sort=bogus", nil, bearer(adminAT)), 400, "invalid_request")
	// The public /v1/me never shows them.
	me := e.api("GET", "/v1/me", nil, bearer(r.str("access_token")))
	if _, ok := me.body["user"].(map[string]any)["last_sign_in_ip"]; ok {
		t.Fatalf("/v1/me leaks admin fields: %s", me.raw)
	}
}

// Repository: RecordSignIn overwrites and never moves activity backwards;
// TouchActive writes only when the stored value is at least minAge old.
func TestUserRepositorySignInAndActivity(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	uid := e.registerVerified("dave", "dave@example.com")
	repo := user.NewUserRepository(e.app.DB)
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

	get := func() *user.User {
		t.Helper()
		u, err := repo.FindByID(ctx, uid)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	updatedAt := get().UpdatedAt
	if err := repo.RecordSignIn(ctx, uid, t0, "saml:corp", "198.51.100.4"); err != nil {
		t.Fatal(err)
	}
	u := get()
	if !u.LastSignInAt.Equal(t0) || *u.LastSignInMethod != "saml:corp" || *u.LastSignInIP != "198.51.100.4" || !u.LastActiveAt.Equal(t0) {
		t.Fatalf("after RecordSignIn: %+v", u)
	}
	if err := repo.RecordSignIn(ctx, "usr_missing", t0, "password", ""); err == nil {
		t.Fatal("RecordSignIn on a missing user must fail")
	}

	wrote, err := repo.TouchActive(ctx, uid, t0.Add(4*time.Minute), 5*time.Minute)
	if err != nil || wrote || !get().LastActiveAt.Equal(t0) {
		t.Fatalf("within interval: wrote=%v err=%v at=%v", wrote, err, get().LastActiveAt)
	}
	t1 := t0.Add(5 * time.Minute)
	if wrote, err = repo.TouchActive(ctx, uid, t1, 5*time.Minute); err != nil || !wrote || !get().LastActiveAt.Equal(t1) {
		t.Fatalf("at interval: wrote=%v err=%v at=%v", wrote, err, get().LastActiveAt)
	}

	// An older sign-in (clock skew between replicas) keeps the newer activity.
	if err := repo.RecordSignIn(ctx, uid, t0.Add(time.Minute), "password", ""); err != nil {
		t.Fatal(err)
	}
	if u := get(); !u.LastActiveAt.Equal(t1) || *u.LastSignInMethod != "password" {
		t.Fatalf("activity went backwards: %+v", u)
	}
	// Activity isn't a profile edit.
	if u := get(); !u.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("updated_at touched: %v -> %v", updatedAt, u.UpdatedAt)
	}

	for _, sort := range []string{"", user.SortCreated, user.SortLastActive, user.SortLastSignIn} {
		if _, n, err := repo.List(ctx, user.ListFilter{Sort: sort, Limit: 10}); err != nil || n != 1 {
			t.Fatalf("List sort=%q: n=%d err=%v", sort, n, err)
		}
	}
}

// Migration 10 backfills from surviving sessions and SSO identities,
// whichever is newer; users never seen stay NULL. Down drops the columns.
func TestMigrationBackfillsLastActive(t *testing.T) {
	e := newEnv(t)
	dsn := e.cfg.DBConfig.URL
	sqldb := e.sqlDB()
	migrateDownTo(t, sqldb, dsn, 9)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqldb.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for _, u := range []string{"usr_s", "usr_i", "usr_both", "usr_none"} {
		exec(`INSERT INTO users (id, username, username_folded) VALUES ($1, $2, $3)`, u, u, u)
	}
	exec(`INSERT INTO identity_providers (id, kind, slug, display_name, config) VALUES ('idp_1', 'oidc', 'corp', 'Corp', '{}')`)
	session := func(id, uid, method, ip, created, seen string) {
		exec(`INSERT INTO sessions (id, user_id, auth_method, ip, created_at, last_seen_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, now())`,
			id, uid, method, ip, created, seen)
	}
	// usr_s: two sessions; sign-in = the newer created_at, active = max last_seen_at (of the older one).
	session("ses_1", "usr_s", "password", "192.0.2.1", "2026-10-01T10:00:00Z", "2026-10-09T10:00:00Z")
	session("ses_2", "usr_s", "oidc:corp", "192.0.2.2", "2026-10-05T10:00:00Z", "2026-10-06T10:00:00Z")
	// usr_i: sessions gone, only an identity login.
	exec(`INSERT INTO user_identities (id, user_id, provider_id, subject, last_login_at) VALUES ('uid_1', 'usr_i', 'idp_1', 'sub-i', '2026-09-01T08:00:00Z')`)
	// usr_both: identity login newer than the surviving session.
	session("ses_3", "usr_both", "password", "192.0.2.3", "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z")
	exec(`INSERT INTO user_identities (id, user_id, provider_id, subject, last_login_at) VALUES ('uid_2', 'usr_both', 'idp_1', 'sub-b', '2026-08-03T00:00:00Z')`)

	if err := db.MigrateUp(dsn); err != nil {
		t.Fatalf("up: %v", err)
	}
	type row struct {
		signIn, active sql.NullTime
		method, ip     sql.NullString
	}
	get := func(id string) row {
		var r row
		if err := sqldb.QueryRow(`SELECT last_sign_in_at, last_sign_in_method, last_sign_in_ip, last_active_at FROM users WHERE id = $1`, id).
			Scan(&r.signIn, &r.method, &r.ip, &r.active); err != nil {
			t.Fatal(err)
		}
		return r
	}
	at := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	check := func(id string, signIn, method, ip, active string) {
		t.Helper()
		r := get(id)
		if (signIn == "") == r.signIn.Valid || (r.signIn.Valid && !r.signIn.Time.Equal(at(signIn))) {
			t.Errorf("%s last_sign_in_at = %v, want %q", id, r.signIn, signIn)
		}
		if r.method.String != method || r.ip.String != ip {
			t.Errorf("%s method/ip = %q/%q, want %q/%q", id, r.method.String, r.ip.String, method, ip)
		}
		if (active == "") == r.active.Valid || (r.active.Valid && !r.active.Time.Equal(at(active))) {
			t.Errorf("%s last_active_at = %v, want %q", id, r.active, active)
		}
	}
	check("usr_s", "2026-10-05T10:00:00Z", "oidc:corp", "192.0.2.2", "2026-10-09T10:00:00Z")
	check("usr_i", "2026-09-01T08:00:00Z", "oidc:corp", "", "2026-09-01T08:00:00Z")
	check("usr_both", "2026-08-03T00:00:00Z", "oidc:corp", "", "2026-08-03T00:00:00Z")
	check("usr_none", "", "", "", "")

	migrateDownTo(t, sqldb, dsn, 9)
	var n int
	if err := sqldb.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_name = 'users' AND column_name LIKE 'last_%'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("columns after down = %d (%v)", n, err)
	}
	if err := db.MigrateUp(dsn); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
