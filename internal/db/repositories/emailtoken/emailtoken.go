// Package emailtoken is the email_tokens repository (verify / reset links).
package emailtoken

import (
	"context"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"gorm.io/gorm/clause"
)

const (
	PurposeVerifyEmail   = "verify_email"
	PurposeResetPassword = "reset_password"
)

type EmailToken struct {
	ID        string
	UserID    string
	Purpose   string
	TokenHash []byte
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

func (EmailToken) TableName() string { return "email_tokens" }

type EmailTokenRepositoryImpl interface {
	Create(ctx context.Context, t *EmailToken) error
	FindByHashForUpdate(ctx context.Context, hash []byte, purpose string) (*EmailToken, error)
	// ConsumeAllForUser marks every unused token of purpose as used.
	ConsumeAllForUser(ctx context.Context, userID, purpose string, at time.Time) error
	DeleteExpiredBefore(ctx context.Context, before time.Time) (int64, error)
}

type EmailTokenRepository struct {
	db *db.DB
}

func NewEmailTokenRepository(d *db.DB) EmailTokenRepositoryImpl {
	return &EmailTokenRepository{db: d}
}

func (r *EmailTokenRepository) Create(ctx context.Context, t *EmailToken) error {
	return r.db.Conn(ctx).Create(t).Error
}

func (r *EmailTokenRepository) FindByHashForUpdate(ctx context.Context, hash []byte, purpose string) (*EmailToken, error) {
	var t EmailToken
	err := r.db.Conn(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("token_hash = ? AND purpose = ?", hash, purpose).First(&t).Error
	if err != nil {
		return nil, repositories.NotFound(err)
	}
	return &t, nil
}

func (r *EmailTokenRepository) ConsumeAllForUser(ctx context.Context, userID, purpose string, at time.Time) error {
	return r.db.Conn(ctx).Model(&EmailToken{}).
		Where("user_id = ? AND purpose = ? AND used_at IS NULL", userID, purpose).Update("used_at", at).Error
}

func (r *EmailTokenRepository) DeleteExpiredBefore(ctx context.Context, before time.Time) (int64, error) {
	res := r.db.Conn(ctx).Where("expires_at < ?", before).Delete(&EmailToken{})
	return res.RowsAffected, res.Error
}
