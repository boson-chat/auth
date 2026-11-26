// Package nickservacct is the repository for nickserv_accounts (local users
// linked to NickServ accounts) and nickserv_lockouts.
package nickservacct

import (
	"context"
	"errors"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/services/nickserv"
	"gorm.io/gorm/clause"
)

// ErrAccountLinked: the NickServ account (or the user) is already linked.
var ErrAccountLinked = errors.New("nickserv account already linked")

// Link is a local user's NickServ account.
type Link struct {
	UserID           string `gorm:"primaryKey"`
	Account          string
	AccountFolded    string
	ServicesID       string
	Strategy         string
	SessionEnc       []byte
	SessionExpiresAt *time.Time
	CreatedAt        time.Time
	LastVerifiedAt   time.Time
}

func (Link) TableName() string { return "nickserv_accounts" }

type lockout struct {
	Key         string `gorm:"primaryKey"`
	Failures    int
	WindowStart time.Time
	LockedUntil *time.Time
	UpdatedAt   time.Time
}

func (lockout) TableName() string { return "nickserv_lockouts" }

type NickServAccountRepositoryImpl interface {
	Create(ctx context.Context, l *Link) error
	FindByAccountFolded(ctx context.Context, folded string) (*Link, error)
	FindByUserID(ctx context.Context, userID string) (*Link, error)
	// Touch records a successful verification: spelling, services id,
	// strategy and the (sealed) services session.
	Touch(ctx context.Context, userID, account, servicesID, strategy string, sessionEnc []byte, sessionExpires *time.Time, at time.Time) error
	// ClearSession forgets the stored services session.
	ClearSession(ctx context.Context, userID string) error
	// DeleteLockoutsBefore removes lockout rows untouched since t.
	DeleteLockoutsBefore(ctx context.Context, t time.Time) (int64, error)
	nickserv.LockoutStore
}

type NickServAccountRepository struct {
	db *db.DB
}

func NewNickServAccountRepository(d *db.DB) NickServAccountRepositoryImpl {
	return &NickServAccountRepository{db: d}
}

func (r *NickServAccountRepository) Create(ctx context.Context, l *Link) error {
	err := r.db.Conn(ctx).Create(l).Error
	if repositories.UniqueViolation(err) != "" {
		return ErrAccountLinked
	}
	return err
}

func (r *NickServAccountRepository) find(ctx context.Context, q string, v string) (*Link, error) {
	if v == "" {
		return nil, repositories.ErrNotFound
	}
	var l Link
	if err := r.db.Conn(ctx).Where(q, v).First(&l).Error; err != nil {
		return nil, repositories.NotFound(err)
	}
	return &l, nil
}

func (r *NickServAccountRepository) FindByAccountFolded(ctx context.Context, folded string) (*Link, error) {
	return r.find(ctx, "account_folded = ?", folded)
}

func (r *NickServAccountRepository) FindByUserID(ctx context.Context, userID string) (*Link, error) {
	return r.find(ctx, "user_id = ?", userID)
}

func (r *NickServAccountRepository) Touch(ctx context.Context, userID, account, servicesID, strategy string, sessionEnc []byte, sessionExpires *time.Time, at time.Time) error {
	fields := map[string]any{
		"account": account, "strategy": strategy, "last_verified_at": at,
		"session_enc": sessionEnc, "session_expires_at": sessionExpires,
	}
	if servicesID != "" {
		fields["services_id"] = servicesID
	}
	res := r.db.Conn(ctx).Model(&Link{}).Where("user_id = ?", userID).Updates(fields)
	if res.Error == nil && res.RowsAffected == 0 {
		return repositories.ErrNotFound
	}
	return res.Error
}

func (r *NickServAccountRepository) ClearSession(ctx context.Context, userID string) error {
	return r.db.Conn(ctx).Model(&Link{}).Where("user_id = ?", userID).
		Updates(map[string]any{"session_enc": nil, "session_expires_at": nil}).Error
}

func (r *NickServAccountRepository) LockedUntil(ctx context.Context, key string, now time.Time) (time.Time, error) {
	var l lockout
	err := r.db.Conn(ctx).Where("key = ? AND locked_until > ?", key, now).First(&l).Error
	if err != nil {
		if errors.Is(repositories.NotFound(err), repositories.ErrNotFound) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	return *l.LockedUntil, nil
}

func (r *NickServAccountRepository) RecordFailure(ctx context.Context, key string, now time.Time, window time.Duration, threshold int, lockFor time.Duration) (time.Time, error) {
	var until time.Time
	err := r.db.WithTx(ctx, func(ctx context.Context) error {
		conn := r.db.Conn(ctx)
		// Make sure the row exists, then lock it: concurrent failures on
		// other replicas count exactly once each.
		if err := conn.Clauses(clause.OnConflict{DoNothing: true}).
			Create(&lockout{Key: key, WindowStart: now, UpdatedAt: now}).Error; err != nil {
			return err
		}
		var l lockout
		if err := conn.Clauses(clause.Locking{Strength: "UPDATE"}).Where("key = ?", key).First(&l).Error; err != nil {
			return err
		}
		var prev time.Time
		if l.LockedUntil != nil {
			prev = *l.LockedUntil
		}
		f, ws, lu := nickserv.NextLockout(l.Failures, l.WindowStart, prev, now, window, threshold, lockFor)
		var lockedUntil *time.Time
		if !lu.IsZero() {
			lockedUntil = &lu
		}
		if lu.After(now) {
			until = lu
		}
		return conn.Model(&lockout{}).Where("key = ?", key).Updates(map[string]any{
			"failures": f, "window_start": ws, "locked_until": lockedUntil, "updated_at": now,
		}).Error
	})
	return until, err
}

func (r *NickServAccountRepository) Reset(ctx context.Context, key string) error {
	return r.db.Conn(ctx).Where("key = ?", key).Delete(&lockout{}).Error
}

func (r *NickServAccountRepository) DeleteLockoutsBefore(ctx context.Context, t time.Time) (int64, error) {
	res := r.db.Conn(ctx).Where("updated_at < ? AND (locked_until IS NULL OR locked_until < ?)", t, t).Delete(&lockout{})
	return res.RowsAffected, res.Error
}
