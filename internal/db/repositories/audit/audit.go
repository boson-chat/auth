// Package audit is the audit_log repository.
package audit

import (
	"context"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
)

type Entry struct {
	ID     string             `json:"id"`
	UserID *string            `json:"user_id"`
	Event  string             `json:"event"`
	IP     string             `json:"ip"`
	Meta   repositories.JSONB `json:"meta"`
	At     time.Time          `json:"at"`
}

func (Entry) TableName() string { return "audit_log" }

type AuditRepositoryImpl interface {
	Create(ctx context.Context, e *Entry) error
	ListByUser(ctx context.Context, userID string, limit int) ([]*Entry, error)
	ListRecent(ctx context.Context, limit int) ([]*Entry, error)
}

type AuditRepository struct {
	db *db.DB
}

func NewAuditRepository(d *db.DB) AuditRepositoryImpl {
	return &AuditRepository{db: d}
}

func (r *AuditRepository) Create(ctx context.Context, e *Entry) error {
	return r.db.Conn(ctx).Create(e).Error
}

func (r *AuditRepository) ListByUser(ctx context.Context, userID string, limit int) ([]*Entry, error) {
	var out []*Entry
	err := r.db.Conn(ctx).Where("user_id = ?", userID).Order("at DESC, id DESC").Limit(limit).Find(&out).Error
	return out, err
}

func (r *AuditRepository) ListRecent(ctx context.Context, limit int) ([]*Entry, error) {
	var out []*Entry
	err := r.db.Conn(ctx).Order("at DESC, id DESC").Limit(limit).Find(&out).Error
	return out, err
}
