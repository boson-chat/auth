// Package accountremoval reads irc_account_removals (migration 7), the
// append-only log of account deletions and disables that database triggers
// on users write. IRC polls it to drop removed accounts.
package accountremoval

import (
	"context"
	"strconv"
	"time"

	"github.com/boson-chat/auth/internal/db"
)

const (
	ReasonDeleted  = "deleted"
	ReasonDisabled = "disabled"
	// Written by auth for federated accounts (migration 16), not by triggers:
	// a blocked home domain, and an admin's revoke-sessions for a domain.
	ReasonDomainBlocked   = "domain_blocked"
	ReasonSessionsRevoked = "sessions_revoked"
)

// Position is a place in the log: entries are ordered by the writing
// transaction's id, then by row id.
type Position struct {
	TxID uint64
	ID   int64
}

// Entry is one log row plus the account's state now.
type Entry struct {
	Position
	UserID         string
	Username       string
	UsernameFolded string
	Reason         string
	At             time.Time
	// UsernameInUse: a user with this folded username exists now (maybe a
	// different, re-created account).
	UsernameInUse bool
	// StillDisabled: user_id still exists and is disabled now.
	StillDisabled bool
	// StillDomainBlocked: user_id is a federated account whose home domain
	// is blocked now, by the block this entry was written for
	// (federated_accounts.domain_blocked_at <= at: an entry from an earlier,
	// lifted block doesn't come back when the domain is blocked again).
	StillDomainBlocked bool
	// NoLoginSince: user_id is a federated account that hasn't signed in
	// since the entry was written.
	NoLoginSince bool
}

type AccountRemovalRepositoryImpl interface {
	// After returns up to limit entries strictly after pos, in log order.
	// Only rows from transactions older than every in-flight transaction are
	// returned, so no row can later appear before the last one returned.
	After(ctx context.Context, pos Position, limit int) ([]*Entry, error)
	// DeleteBefore prunes entries written before t.
	DeleteBefore(ctx context.Context, t time.Time) (int64, error)
}

type AccountRemovalRepository struct {
	db *db.DB
}

func NewAccountRemovalRepository(d *db.DB) AccountRemovalRepositoryImpl {
	return &AccountRemovalRepository{db: d}
}

type row struct {
	ID             int64
	TxID           string
	UserID         string
	Username       string
	UsernameFolded string
	Reason         string
	At             time.Time
	UsernameInUse  bool
	StillDisabled  bool
	// StillDomainBlocked / NoLoginSince: see Entry.
	StillDomainBlocked bool
	NoLoginSince       bool
}

func (r *AccountRemovalRepository) After(ctx context.Context, pos Position, limit int) ([]*Entry, error) {
	var rows []row
	err := r.db.Conn(ctx).Raw(`
SELECT r.id, r.txid::text AS tx_id, r.user_id, r.username, r.username_folded, r.reason, r.at,
       EXISTS (SELECT 1 FROM users u WHERE u.username_folded = r.username_folded) AS username_in_use,
       EXISTS (SELECT 1 FROM users u WHERE u.id = r.user_id AND u.disabled_at IS NOT NULL) AS still_disabled,
       EXISTS (SELECT 1 FROM federated_accounts f WHERE f.user_id = r.user_id AND f.domain_blocked_at <= r.at) AS still_domain_blocked,
       EXISTS (SELECT 1 FROM federated_accounts f WHERE f.user_id = r.user_id AND f.last_login_at <= r.at) AS no_login_since
FROM irc_account_removals r
WHERE (r.txid, r.id) > (CAST(? AS text)::xid8, ?)
  AND r.txid < pg_snapshot_xmin(pg_current_snapshot())
ORDER BY r.txid, r.id
LIMIT ?`, strconv.FormatUint(pos.TxID, 10), pos.ID, limit).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]*Entry, 0, len(rows))
	for _, x := range rows {
		txid, err := strconv.ParseUint(x.TxID, 10, 64)
		if err != nil {
			return nil, err
		}
		out = append(out, &Entry{
			Position: Position{TxID: txid, ID: x.ID}, UserID: x.UserID, Username: x.Username,
			UsernameFolded: x.UsernameFolded, Reason: x.Reason, At: x.At,
			UsernameInUse: x.UsernameInUse, StillDisabled: x.StillDisabled,
			StillDomainBlocked: x.StillDomainBlocked, NoLoginSince: x.NoLoginSince,
		})
	}
	return out, nil
}

func (r *AccountRemovalRepository) DeleteBefore(ctx context.Context, t time.Time) (int64, error) {
	res := r.db.Conn(ctx).Exec(`DELETE FROM irc_account_removals WHERE at < ?`, t)
	return res.RowsAffected, res.Error
}
