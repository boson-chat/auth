// Package credential is the password_credentials repository.
package credential

import (
	"context"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"gorm.io/gorm/clause"
)

type PasswordCredential struct {
	UserID    string `gorm:"primaryKey"`
	Hash      string
	UpdatedAt time.Time
}

func (PasswordCredential) TableName() string { return "password_credentials" }

type CredentialRepositoryImpl interface {
	Get(ctx context.Context, userID string) (*PasswordCredential, error)
	Upsert(ctx context.Context, userID, hash string) error
}

type CredentialRepository struct {
	db *db.DB
}

func NewCredentialRepository(d *db.DB) CredentialRepositoryImpl {
	return &CredentialRepository{db: d}
}

func (r *CredentialRepository) Get(ctx context.Context, userID string) (*PasswordCredential, error) {
	var c PasswordCredential
	if err := r.db.Conn(ctx).Where("user_id = ?", userID).First(&c).Error; err != nil {
		return nil, repositories.NotFound(err)
	}
	return &c, nil
}

func (r *CredentialRepository) Upsert(ctx context.Context, userID, hash string) error {
	return r.db.Conn(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"hash", "updated_at"}),
	}).Create(&PasswordCredential{UserID: userID, Hash: hash, UpdatedAt: time.Now().UTC()}).Error
}
