// Package session is the sessions repository.
package session

import (
	"context"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"gorm.io/gorm/clause"
)

type Session struct {
	ID         string
	UserID     string
	AuthMethod string
	IP         string
	UserAgent  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
}

func (Session) TableName() string { return "sessions" }

// Active reports whether the session can still be used at now.
func (s *Session) Active(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}

type SessionRepositoryImpl interface {
	Create(ctx context.Context, s *Session) error
	FindByID(ctx context.Context, id string) (*Session, error)
	// FindByIDForUpdate locks the row until the surrounding transaction ends.
	FindByIDForUpdate(ctx context.Context, id string) (*Session, error)
	ListActiveByUser(ctx context.Context, userID string, now time.Time) ([]*Session, error)
	Touch(ctx context.Context, id string, at time.Time, ip, userAgent string) error
	// Revoke revokes one active session; false if it was not active.
	Revoke(ctx context.Context, id string, at time.Time) (bool, error)
	// RevokeAllForUser revokes every active session except exceptID ("" = none).
	RevokeAllForUser(ctx context.Context, userID, exceptID string, at time.Time) (int64, error)
	DeleteExpiredBefore(ctx context.Context, before time.Time) (int64, error)
}

type SessionRepository struct {
	db *db.DB
}

func NewSessionRepository(d *db.DB) SessionRepositoryImpl {
	return &SessionRepository{db: d}
}

func (r *SessionRepository) Create(ctx context.Context, s *Session) error {
	return r.db.Conn(ctx).Create(s).Error
}

func (r *SessionRepository) FindByID(ctx context.Context, id string) (*Session, error) {
	var s Session
	if err := r.db.Conn(ctx).Where("id = ?", id).First(&s).Error; err != nil {
		return nil, repositories.NotFound(err)
	}
	return &s, nil
}

func (r *SessionRepository) FindByIDForUpdate(ctx context.Context, id string) (*Session, error) {
	var s Session
	err := r.db.Conn(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id).First(&s).Error
	if err != nil {
		return nil, repositories.NotFound(err)
	}
	return &s, nil
}

func (r *SessionRepository) ListActiveByUser(ctx context.Context, userID string, now time.Time) ([]*Session, error) {
	var out []*Session
	err := r.db.Conn(ctx).
		Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, now).
		Order("last_seen_at DESC").Find(&out).Error
	return out, err
}

func (r *SessionRepository) Touch(ctx context.Context, id string, at time.Time, ip, userAgent string) error {
	return r.db.Conn(ctx).Model(&Session{}).Where("id = ?", id).
		Updates(map[string]any{"last_seen_at": at, "ip": ip, "user_agent": userAgent}).Error
}

func (r *SessionRepository) Revoke(ctx context.Context, id string, at time.Time) (bool, error) {
	res := r.db.Conn(ctx).Model(&Session{}).Where("id = ? AND revoked_at IS NULL", id).Update("revoked_at", at)
	return res.RowsAffected > 0, res.Error
}

func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID, exceptID string, at time.Time) (int64, error) {
	q := r.db.Conn(ctx).Model(&Session{}).Where("user_id = ? AND revoked_at IS NULL", userID)
	if exceptID != "" {
		q = q.Where("id <> ?", exceptID)
	}
	res := q.Update("revoked_at", at)
	return res.RowsAffected, res.Error
}

func (r *SessionRepository) DeleteExpiredBefore(ctx context.Context, before time.Time) (int64, error) {
	res := r.db.Conn(ctx).Where("expires_at < ?", before).Delete(&Session{})
	return res.RowsAffected, res.Error
}
