package bridge

import (
	"context"
	"database/sql"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"gorm.io/gorm"
)

// Change is one claimed outbox row (migration 15).
type Change struct {
	ID       int64
	UserID   string
	Username string
	Attempts int
}

// Status is the outbox and full sync state (GET /internal/v1/bridge/status).
type Status struct {
	Enabled            bool       `json:"enabled"`
	Pending            int64      `json:"pending"`
	Failing            int64      `json:"failing"`
	OldestPending      *time.Time `json:"oldest_pending"`
	LastError          string     `json:"last_error,omitempty"`
	LastReconcileAt    *time.Time `json:"last_reconcile_at"`
	LastReconcileError string     `json:"last_reconcile_error,omitempty"`
}

// Store is the bridge's tables.
type Store interface {
	// SetEnabled turns the outbox triggers on or off. Off also empties the
	// outbox (a full sync catches up when it's back on).
	SetEnabled(ctx context.Context, on bool) error
	// Claim takes up to limit users with a due change, and all their
	// changes, for lease.
	Claim(ctx context.Context, limit int, lease time.Duration) ([]Change, error)
	Done(ctx context.Context, ids []int64) error
	// Retry puts changes back, due after backoff(their attempts + 1).
	Retry(ctx context.Context, ids []int64, errText string, backoff func(attempts int) time.Duration) error
	User(ctx context.Context, id string) (*User, error) // nil, nil: gone
	Users(ctx context.Context) ([]User, error)
	Pending(ctx context.Context) (int64, error)
	// LeaseReconcile takes the full sync lease; false if another holds it.
	LeaseReconcile(ctx context.Context, d time.Duration) (bool, error)
	ReconcileDone(ctx context.Context, errText string) error
	Status(ctx context.Context) (Status, error)
}

type pgStore struct{ db *db.DB }

// NewStore is the Postgres store.
func NewStore(d *db.DB) Store { return &pgStore{db: d} }

func (s *pgStore) conn(ctx context.Context) *gorm.DB { return s.db.Conn(ctx) }

func (s *pgStore) SetEnabled(ctx context.Context, on bool) error {
	return s.db.WithTx(ctx, func(ctx context.Context) error {
		if err := s.conn(ctx).Exec(`UPDATE bridge_state SET enabled = ? WHERE id AND enabled <> ?`, on, on).Error; err != nil {
			return err
		}
		if on {
			return nil
		}
		return s.conn(ctx).Exec(`DELETE FROM bridge_outbox`).Error
	})
}

func (s *pgStore) Claim(ctx context.Context, limit int, lease time.Duration) ([]Change, error) {
	var out []Change
	err := s.conn(ctx).Raw(`
WITH due AS (
    SELECT user_id FROM bridge_outbox
    WHERE next_attempt_at <= now() AND (claimed_until IS NULL OR claimed_until < now())
    GROUP BY user_id ORDER BY min(id) LIMIT ?
)
UPDATE bridge_outbox o SET claimed_until = now() + make_interval(secs => ?)
FROM due
WHERE o.user_id = due.user_id AND (o.claimed_until IS NULL OR o.claimed_until < now())
RETURNING o.id, o.user_id, o.username, o.attempts`, limit, lease.Seconds()).Scan(&out).Error
	return out, err
}

func (s *pgStore) Done(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	return s.conn(ctx).Exec(`DELETE FROM bridge_outbox WHERE id IN ?`, ids).Error
}

func (s *pgStore) Retry(ctx context.Context, ids []int64, errText string, backoff func(int) time.Duration) error {
	if len(ids) == 0 {
		return nil
	}
	var max struct{ Attempts int }
	if err := s.conn(ctx).Raw(`SELECT coalesce(max(attempts), 0) AS attempts FROM bridge_outbox WHERE id IN ?`, ids).Scan(&max).Error; err != nil {
		return err
	}
	n := max.Attempts + 1
	return s.conn(ctx).Exec(`UPDATE bridge_outbox SET attempts = ?, last_error = ?, claimed_until = NULL,
		next_attempt_at = now() + make_interval(secs => ?) WHERE id IN ?`, n, errText, backoff(n).Seconds(), ids).Error
}

type userRow struct {
	ID              string
	Username        string
	Email           string
	DisplayName     string
	Disabled        bool
	NickServAccount string
}

const usersQuery = `SELECT u.id, u.username::text AS username, coalesce(u.email::text, '') AS email, u.display_name,
	u.disabled_at IS NOT NULL AS disabled, coalesce(n.account, '') AS nick_serv_account
FROM users u LEFT JOIN nickserv_accounts n ON n.user_id = u.id`

func (r userRow) user() User {
	return User{ID: r.ID, Username: r.Username, Email: r.Email, DisplayName: r.DisplayName, Disabled: r.Disabled, NickServAccount: r.NickServAccount}
}

func (s *pgStore) User(ctx context.Context, id string) (*User, error) {
	var rows []userRow
	if err := s.conn(ctx).Raw(usersQuery+` WHERE u.id = ?`, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	u := rows[0].user()
	return &u, nil
}

func (s *pgStore) Users(ctx context.Context) ([]User, error) {
	var rows []userRow
	if err := s.conn(ctx).Raw(usersQuery + ` ORDER BY u.created_at, u.id`).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]User, len(rows))
	for i, r := range rows {
		out[i] = r.user()
	}
	return out, nil
}

func (s *pgStore) Pending(ctx context.Context) (int64, error) {
	var n int64
	err := s.conn(ctx).Raw(`SELECT count(*) FROM bridge_outbox`).Scan(&n).Error
	return n, err
}

func (s *pgStore) LeaseReconcile(ctx context.Context, d time.Duration) (bool, error) {
	res := s.conn(ctx).Exec(`UPDATE bridge_state SET reconcile_lease_until = now() + make_interval(secs => ?)
		WHERE id AND (reconcile_lease_until IS NULL OR reconcile_lease_until < now())`, d.Seconds())
	return res.RowsAffected == 1, res.Error
}

func (s *pgStore) ReconcileDone(ctx context.Context, errText string) error {
	var e *string
	if errText != "" {
		e = &errText
	}
	return s.conn(ctx).Exec(`UPDATE bridge_state SET reconcile_lease_until = NULL, last_reconcile_at = now(),
		last_reconcile_error = ? WHERE id`, e).Error
}

func (s *pgStore) Status(ctx context.Context) (Status, error) {
	var st Status
	var row struct {
		Enabled            bool
		LastReconcileAt    sql.NullTime
		LastReconcileError sql.NullString
		Pending            int64
		Failing            int64
		OldestPending      sql.NullTime
		LastError          sql.NullString
	}
	err := s.conn(ctx).Raw(`SELECT s.enabled, s.last_reconcile_at, s.last_reconcile_error,
	(SELECT count(*) FROM bridge_outbox) AS pending,
	(SELECT count(*) FROM bridge_outbox WHERE attempts > 0) AS failing,
	(SELECT min(created_at) FROM bridge_outbox) AS oldest_pending,
	(SELECT last_error FROM bridge_outbox WHERE last_error IS NOT NULL ORDER BY id DESC LIMIT 1) AS last_error
FROM bridge_state s WHERE s.id`).Scan(&row).Error
	if err != nil {
		return st, err
	}
	st.Enabled, st.Pending, st.Failing = row.Enabled, row.Pending, row.Failing
	if row.OldestPending.Valid {
		st.OldestPending = &row.OldestPending.Time
	}
	if row.LastReconcileAt.Valid {
		st.LastReconcileAt = &row.LastReconcileAt.Time
	}
	st.LastError, st.LastReconcileError = row.LastError.String, row.LastReconcileError.String
	return st, nil
}
