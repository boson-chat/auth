// Package ssocode is the sso_login_codes repository: single-use codes that
// native clients exchange for a session after an SSO login.
package ssocode

import (
	"context"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"gorm.io/gorm/clause"
)

type Code struct {
	ID            string
	CodeHash      []byte
	UserID        string
	ProviderID    string
	AuthMethod    string
	CodeChallenge string
	ExpiresAt     time.Time
	UsedAt        *time.Time
	CreatedAt     time.Time
}

func (Code) TableName() string { return "sso_login_codes" }

type SSOCodeRepositoryImpl interface {
	Create(ctx context.Context, c *Code) error
	// Consume marks the unused, unexpired code with that hash used and
	// returns it; ErrNotFound otherwise. Atomic, so a code works once.
	Consume(ctx context.Context, hash []byte, now time.Time) (*Code, error)
	DeleteExpiredBefore(ctx context.Context, t time.Time) (int64, error)
}

type SSOCodeRepository struct {
	db *db.DB
}

func NewSSOCodeRepository(d *db.DB) SSOCodeRepositoryImpl {
	return &SSOCodeRepository{db: d}
}

func (r *SSOCodeRepository) Create(ctx context.Context, c *Code) error {
	return r.db.Conn(ctx).Create(c).Error
}

func (r *SSOCodeRepository) Consume(ctx context.Context, hash []byte, now time.Time) (*Code, error) {
	var out []*Code
	res := r.db.Conn(ctx).Model(&out).Clauses(clause.Returning{}).
		Where("code_hash = ? AND used_at IS NULL AND expires_at > ?", hash, now).
		Update("used_at", now)
	if res.Error != nil {
		return nil, res.Error
	}
	if len(out) == 0 {
		return nil, repositories.ErrNotFound
	}
	return out[0], nil
}

func (r *SSOCodeRepository) DeleteExpiredBefore(ctx context.Context, t time.Time) (int64, error) {
	res := r.db.Conn(ctx).Where("expires_at < ?", t).Delete(&Code{})
	return res.RowsAffected, res.Error
}
