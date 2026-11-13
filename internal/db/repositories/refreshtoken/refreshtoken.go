// Package refreshtoken is the refresh_tokens repository. Only SHA-256
// digests of tokens are stored.
package refreshtoken

import (
	"context"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"gorm.io/gorm/clause"
)

type RefreshToken struct {
	ID        string
	SessionID string
	FamilyID  string
	TokenHash []byte
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

func (RefreshToken) TableName() string { return "refresh_tokens" }

type RefreshTokenRepositoryImpl interface {
	Create(ctx context.Context, t *RefreshToken) error
	FindByHash(ctx context.Context, hash []byte) (*RefreshToken, error)
	// FindByHashForUpdate locks the row until the surrounding transaction ends,
	// so two concurrent refreshes with one token serialise.
	FindByHashForUpdate(ctx context.Context, hash []byte) (*RefreshToken, error)
	MarkUsed(ctx context.Context, id string, at time.Time) error
	RevokeFamily(ctx context.Context, familyID string, at time.Time) error
	RevokeBySession(ctx context.Context, sessionID string, at time.Time) error
	RevokeByUser(ctx context.Context, userID, exceptSessionID string, at time.Time) error
	DeleteExpiredBefore(ctx context.Context, before time.Time) (int64, error)
}

type RefreshTokenRepository struct {
	db *db.DB
}

func NewRefreshTokenRepository(d *db.DB) RefreshTokenRepositoryImpl {
	return &RefreshTokenRepository{db: d}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, t *RefreshToken) error {
	return r.db.Conn(ctx).Create(t).Error
}

func (r *RefreshTokenRepository) FindByHash(ctx context.Context, hash []byte) (*RefreshToken, error) {
	var t RefreshToken
	if err := r.db.Conn(ctx).Where("token_hash = ?", hash).First(&t).Error; err != nil {
		return nil, repositories.NotFound(err)
	}
	return &t, nil
}

func (r *RefreshTokenRepository) FindByHashForUpdate(ctx context.Context, hash []byte) (*RefreshToken, error) {
	var t RefreshToken
	err := r.db.Conn(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).Where("token_hash = ?", hash).First(&t).Error
	if err != nil {
		return nil, repositories.NotFound(err)
	}
	return &t, nil
}

func (r *RefreshTokenRepository) MarkUsed(ctx context.Context, id string, at time.Time) error {
	return r.db.Conn(ctx).Model(&RefreshToken{}).Where("id = ?", id).Update("used_at", at).Error
}

func (r *RefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string, at time.Time) error {
	return r.db.Conn(ctx).Model(&RefreshToken{}).
		Where("family_id = ? AND revoked_at IS NULL", familyID).Update("revoked_at", at).Error
}

func (r *RefreshTokenRepository) RevokeBySession(ctx context.Context, sessionID string, at time.Time) error {
	return r.db.Conn(ctx).Model(&RefreshToken{}).
		Where("session_id = ? AND revoked_at IS NULL", sessionID).Update("revoked_at", at).Error
}

func (r *RefreshTokenRepository) RevokeByUser(ctx context.Context, userID, exceptSessionID string, at time.Time) error {
	sub := r.db.Conn(ctx).Table("sessions").Select("id").Where("user_id = ?", userID)
	if exceptSessionID != "" {
		sub = sub.Where("id <> ?", exceptSessionID)
	}
	return r.db.Conn(ctx).Model(&RefreshToken{}).
		Where("session_id IN (?) AND revoked_at IS NULL", sub).Update("revoked_at", at).Error
}

func (r *RefreshTokenRepository) DeleteExpiredBefore(ctx context.Context, before time.Time) (int64, error) {
	res := r.db.Conn(ctx).Where("expires_at < ?", before).Delete(&RefreshToken{})
	return res.RowsAffected, res.Error
}
