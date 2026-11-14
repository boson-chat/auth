package integration

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/db"
)

// removedFeed polls GET /internal/v1/irc/accounts/removed.
func (e *env) removedFeed(since string, limit int) (string, string) {
	e.t.Helper()
	q := "?since=" + since
	if limit > 0 {
		q += fmt.Sprintf("&limit=%d", limit)
	}
	r := e.internalAPI("GET", "/internal/v1/irc/accounts/removed"+q, nil)
	e.expect(r, 200, "")
	if _, ok := r.body["accounts"].([]any); !ok {
		e.t.Fatalf("accounts must be an array: %s", r.raw)
	}
	var out []string
	for _, a := range r.list("accounts") {
		at, err := time.Parse(time.RFC3339, a["at"].(string))
		if err != nil || at.Location() != time.UTC || !strings.HasSuffix(a["at"].(string), "Z") {
			e.t.Fatalf("at must be RFC 3339 UTC: %s", r.raw)
		}
		out = append(out, fmt.Sprintf("%v:%v", a["username"], a["reason"]))
	}
	return strings.Join(out, " "), r.str("next")
}

func TestIRCRemovedAccountsFeed(t *testing.T) {
	e := newEnv(t)
	ownerAT := e.ownerToken("boss")
	aliceID := e.registerVerified("Alice", "alice@example.com")
	bobID := e.registerVerified("bob", "bob@example.com")
	carlID := e.registerVerified("carl", "carl@example.com")
	doraID := e.registerVerified("dora", "dora@example.com")
	sqldb, err := sql.Open("pgx", e.cfg.DBConfig.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer sqldb.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqldb.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}

	// Same auth as the rest of the internal API; not on the public listener.
	e.expect(e.do(e.internal, "GET", "/internal/v1/irc/accounts/removed", nil), 401, "unauthenticated")
	e.expect(e.api("GET", "/internal/v1/irc/accounts/removed", nil, header("X-Internal-Token", e.cfg.InternalConfig.APIToken)), 404, "")
	for _, q := range []string{"?limit=0", "?limit=1001", "?limit=x", "?since=nope", "?since=1.2.3", "?since=-1.1"} {
		e.expect(e.internalAPI("GET", "/internal/v1/irc/accounts/removed"+q, nil), 400, "invalid_request")
	}

	got, next := e.removedFeed("", 0)
	if got != "" || next != "" {
		t.Fatalf("empty feed: %q next %q", got, next)
	}

	// Disable via the admin API, delete via SQL (as any other path would).
	e.expect(e.api("POST", "/v1/admin/users/"+bobID+"/disable", nil, bearer(ownerAT)), 200, "")
	// Disabling an already disabled account adds nothing.
	exec(`UPDATE users SET disabled_at = now() WHERE id = $1`, bobID)
	exec(`DELETE FROM users WHERE id = $1`, aliceID)
	// carl: disabled then re-enabled → skipped.
	e.expect(e.api("POST", "/v1/admin/users/"+carlID+"/disable", nil, bearer(ownerAT)), 200, "")
	e.expect(e.api("POST", "/v1/admin/users/"+carlID+"/enable", nil, bearer(ownerAT)), 200, "")
	// dora: disabled then deleted → only the deletion.
	e.expect(e.api("POST", "/v1/admin/users/"+doraID+"/disable", nil, bearer(ownerAT)), 200, "")
	exec(`DELETE FROM users WHERE id = $1`, doraID)

	got, next = e.removedFeed("", 0)
	if got != "bob:disabled Alice:deleted dora:deleted" || next == "" {
		t.Fatalf("feed: %q next %q", got, next)
	}
	// Caught up: nothing new, next stays.
	if got2, next2 := e.removedFeed(next, 0); got2 != "" || next2 != next {
		t.Fatalf("caught up: %q next %q (want %q)", got2, next2, next)
	}

	// Paging walks the same entries; filtered rows still move the cursor.
	var pages []string
	cur := ""
	for range 10 {
		g, n := e.removedFeed(cur, 1)
		if n == cur {
			break
		}
		if g != "" {
			pages = append(pages, g)
		}
		cur = n
	}
	if strings.Join(pages, " ") != "bob:disabled Alice:deleted dora:deleted" || cur != next {
		t.Fatalf("paged: %v ended at %q, want %q", pages, cur, next)
	}

	// Re-created under the same name (RFC 1459 folding): the old deletion is
	// no longer reported, so IRC never wipes the new person's account.
	e.registerVerified("ALICE", "alice2@example.com")
	if got, _ := e.removedFeed("", 0); got != "bob:disabled dora:deleted" {
		t.Fatalf("after re-create: %q", got)
	}
	// Re-enabling bob drops his entry too.
	e.expect(e.api("POST", "/v1/admin/users/"+bobID+"/enable", nil, bearer(ownerAT)), 200, "")
	if got, _ := e.removedFeed("", 0); got != "dora:deleted" {
		t.Fatalf("after enable: %q", got)
	}

	// Stored rows keep the user id and the name at the time.
	var uid, folded string
	if err := sqldb.QueryRow(`SELECT user_id, username_folded FROM irc_account_removals WHERE username = 'Alice'`).Scan(&uid, &folded); err != nil ||
		uid != aliceID || folded != "alice" {
		t.Fatalf("stored: %q %q %v", uid, folded, err)
	}
}

// A row written by a transaction that commits after a later one must not be
// skipped: the feed holds back everything from transactions that are still
// running, so the cursor can never move past it.
func TestIRCRemovedAccountsFeedWaitsForInFlightTransactions(t *testing.T) {
	e := newEnv(t)
	e.ownerToken("boss")
	slowID := e.registerVerified("slow", "slow@example.com")
	fastID := e.registerVerified("fast", "fast@example.com")
	sqldb, err := sql.Open("pgx", e.cfg.DBConfig.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer sqldb.Close()
	ctx := context.Background()

	_, start := e.removedFeed("", 0)
	slow, err := sqldb.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = slow.Rollback() }()
	// The slow transaction takes its txid (and its log row id) first...
	if _, err := slow.Exec(`DELETE FROM users WHERE id = $1`, slowID); err != nil {
		t.Fatal(err)
	}
	// ...but a later transaction commits first.
	if _, err := sqldb.Exec(`DELETE FROM users WHERE id = $1`, fastID); err != nil {
		t.Fatal(err)
	}
	var committed int
	if err := sqldb.QueryRow(`SELECT count(*) FROM irc_account_removals`).Scan(&committed); err != nil || committed != 1 {
		t.Fatalf("committed rows = %d (%v)", committed, err)
	}
	// fast's row is committed but held back while slow is in flight.
	got, next := e.removedFeed(start, 0)
	if got != "" || next != start {
		t.Fatalf("in flight: %q next %q, want nothing", got, next)
	}
	if err := slow.Commit(); err != nil {
		t.Fatal(err)
	}
	got, next = e.removedFeed(next, 0)
	if got != "slow:deleted fast:deleted" {
		t.Fatalf("after commit: %q", got)
	}
	if got, _ := e.removedFeed(next, 0); got != "" {
		t.Fatalf("replayed: %q", got)
	}

	// Rolled-back removals never appear.
	gone := e.registerVerified("ghost", "ghost@example.com")
	tx, err := sqldb.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE id = $1`, gone); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback()
	if got, _ := e.removedFeed(next, 0); got != "" {
		t.Fatalf("rolled back: %q", got)
	}
}

func TestIRCRemovedAccountsPrune(t *testing.T) {
	e := newEnv(t)
	e.ownerToken("boss")
	oldID := e.registerVerified("old", "old@example.com")
	newID := e.registerVerified("new", "new@example.com")
	sqldb, err := sql.Open("pgx", e.cfg.DBConfig.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer sqldb.Close()
	for _, id := range []string{oldID, newID} {
		if _, err := sqldb.Exec(`DELETE FROM users WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sqldb.Exec(`UPDATE irc_account_removals SET at = now() - interval '181 days' WHERE username = 'old'`); err != nil {
		t.Fatal(err)
	}
	if err := e.app.IRCAccounts.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.removedFeed("", 0); got != "new:deleted" {
		t.Fatalf("after prune: %q", got)
	}
}

// Migration 7 down removes the feed and its triggers; up restores them.
func TestMigrationIRCAccountRemovalsDownUp(t *testing.T) {
	e := newEnv(t)
	dsn := e.cfg.DBConfig.URL
	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sqldb.Close()
	migrateDownTo(t, sqldb, dsn, 6)
	var n int
	if err := sqldb.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_name = 'irc_account_removals'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("table after down = %d (%v)", n, err)
	}
	// Users can still be deleted and disabled without the triggers.
	uid := e.registerVerified("down", "down@example.com")
	if _, err := sqldb.Exec(`UPDATE users SET disabled_at = now() WHERE id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := sqldb.Exec(`DELETE FROM users WHERE id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateUp(dsn); err != nil {
		t.Fatalf("up: %v", err)
	}
	uid = e.registerVerified("up", "up@example.com")
	if _, err := sqldb.Exec(`DELETE FROM users WHERE id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.removedFeed("", 0); got != "up:deleted" {
		t.Fatalf("after up: %q", got)
	}
}
