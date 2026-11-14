package integration

import (
	"database/sql"
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
