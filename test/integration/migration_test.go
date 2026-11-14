package integration

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/boson-chat/auth/db"
)

// Rolling back to 1.2's schema and forward again keeps data and backfills
// audit_log.target_user_id from the old meta.user_id convention.
func TestMigrationDownUpBackfillsAuditTarget(t *testing.T) {
	e := newEnv(t)
	uid := e.registerVerified("legacy", "legacy@example.com")
	dsn := e.cfg.DBConfig.URL
	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sqldb.Close()

	var version int
	if err := sqldb.QueryRow(`SELECT version FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateDown(dsn, version-1); err != nil {
		t.Fatalf("down to 1: %v", err)
	}
	if _, err := sqldb.Exec(`INSERT INTO audit_log (id, user_id, event, meta) VALUES ('aud_old', NULL, 'admin_user_disabled', jsonb_build_object('user_id', $1::text))`, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := sqldb.Exec(`INSERT INTO audit_log (id, event, meta) VALUES ('aud_gone', 'admin_user_disabled', '{"user_id":"usr_deleted"}')`); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateUp(dsn); err != nil {
		t.Fatalf("up: %v", err)
	}
	var target sql.NullString
	if err := sqldb.QueryRow(`SELECT target_user_id FROM audit_log WHERE id = 'aud_old'`).Scan(&target); err != nil {
		t.Fatal(err)
	}
	if target.String != uid {
		t.Fatalf("backfilled target = %q, want %q", target.String, uid)
	}
	if err := sqldb.QueryRow(`SELECT target_user_id FROM audit_log WHERE id = 'aud_gone'`).Scan(&target); err != nil || target.Valid {
		t.Fatalf("dangling user id must stay NULL: %v %v", target, err)
	}
	var n int
	if err := sqldb.QueryRow(`SELECT count(*) FROM network_settings`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("network_settings rows = %d (%v)", n, err)
	}
	e.expect(e.login("legacy", pw), 200, "")
}

// Migration 4 maps 1.x admins onto roles: the earliest admin (and thelion,
// whatever their old role) become Owner, other admins Admin, and down keeps
// users.role.
func TestMigrationMapsAdminsToRoles(t *testing.T) {
	e := newEnv(t)
	dsn := e.cfg.DBConfig.URL
	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sqldb.Close()
	if err := db.MigrateDown(dsn, 1); err != nil {
		t.Fatalf("down: %v", err)
	}
	for _, u := range []struct{ id, name, role, at string }{
		{"usr_01", "first", "admin", "2025-01-01"},
		{"usr_02", "second", "admin", "2025-02-01"},
		{"usr_03", "TheLion", "user", "2025-03-01"},
		{"usr_04", "plain", "user", "2024-01-01"},
	} {
		if _, err := sqldb.Exec(`INSERT INTO users (id, username, username_folded, role, created_at) VALUES ($1, $2, $3, $4, $5)`,
			u.id, u.name, strings.ToLower(u.name), u.role, u.at); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.MigrateUp(dsn); err != nil {
		t.Fatalf("up: %v", err)
	}
	rolesOf := func(uid string) string {
		var s sql.NullString
		if err := sqldb.QueryRow(`SELECT string_agg(r.slug, ',' ORDER BY r.position DESC) FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1`, uid).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s.String
	}
	legacy := func(uid string) string {
		var s string
		if err := sqldb.QueryRow(`SELECT role FROM users WHERE id = $1`, uid).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	for uid, want := range map[string][2]string{
		"usr_01": {"owner", "admin"}, "usr_02": {"admin", "admin"}, "usr_03": {"owner", "admin"}, "usr_04": {"", "user"},
	} {
		if got := rolesOf(uid); got != want[0] {
			t.Errorf("%s roles = %q, want %q", uid, got, want[0])
		}
		if got := legacy(uid); got != want[1] {
			t.Errorf("%s users.role = %q, want %q", uid, got, want[1])
		}
	}
	var n int
	if err := sqldb.QueryRow(`SELECT count(*) FROM roles WHERE builtin IS NOT NULL`).Scan(&n); err != nil || n != 4 {
		t.Fatalf("builtin roles = %d (%v)", n, err)
	}
	// Down drops the tables but keeps the 1.x role column; up again re-seeds.
	if err := db.MigrateDown(dsn, 1); err != nil {
		t.Fatalf("down again: %v", err)
	}
	if legacy("usr_03") != "admin" {
		t.Fatal("down must keep users.role")
	}
	if err := sqldb.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_name IN ('roles', 'user_roles')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tables after down = %d (%v)", n, err)
	}
	if err := db.MigrateUp(dsn); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if rolesOf("usr_01") != "owner" || rolesOf("usr_03") != "owner" {
		t.Fatal("re-applied migration must map the same owners")
	}
}
