// Package invite is the invites repository. Codes are stored as SHA-256.
package invite

import (
	"context"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Invite struct {
	ID        string
	CodeHash  []byte
	CreatedBy *string
	Note      string
	MaxUses   int
	Uses      int
	ExpiresAt *time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

func (Invite) TableName() string { return "invites" }

// Usable reports whether the invite can admit another registration at now.
func (i *Invite) Usable(now time.Time) bool {
	return i.RevokedAt == nil && i.Uses < i.MaxUses && (i.ExpiresAt == nil || now.Before(*i.ExpiresAt))
}

type InviteRepositoryImpl interface {
	Create(ctx context.Context, i *Invite) error
	FindByHashForUpdate(ctx context.Context, hash []byte) (*Invite, error)
	IncrementUses(ctx context.Context, id string) error
	List(ctx context.Context, limit int) ([]*Invite, error)
	Revoke(ctx context.Context, id string, at time.Time) error
}

type InviteRepository struct {
	db *db.DB
}

func NewInviteRepository(d *db.DB) InviteRepositoryImpl {
	return &InviteRepository{db: d}
}

func (r *InviteRepository) Create(ctx context.Context, i *Invite) error {
	return r.db.Conn(ctx).Create(i).Error
}

func (r *InviteRepository) FindByHashForUpdate(ctx context.Context, hash []byte) (*Invite, error) {
	var i Invite
	err := r.db.Conn(ctx).Clauses(clause.Locking{Strength: "UPDATE"}).Where("code_hash = ?", hash).First(&i).Error
	if err != nil {
		return nil, repositories.NotFound(err)
	}
	return &i, nil
}

func (r *InviteRepository) IncrementUses(ctx context.Context, id string) error {
	return r.db.Conn(ctx).Model(&Invite{}).Where("id = ?", id).Update("uses", gorm.Expr("uses + 1")).Error
}

func (r *InviteRepository) List(ctx context.Context, limit int) ([]*Invite, error) {
	var out []*Invite
	err := r.db.Conn(ctx).Order("created_at DESC").Limit(limit).Find(&out).Error
	return out, err
}

func (r *InviteRepository) Revoke(ctx context.Context, id string, at time.Time) error {
	res := r.db.Conn(ctx).Model(&Invite{}).Where("id = ? AND revoked_at IS NULL", id).Update("revoked_at", at)
	if res.Error == nil && res.RowsAffected == 0 {
		return repositories.ErrNotFound
	}
	return res.Error
}
