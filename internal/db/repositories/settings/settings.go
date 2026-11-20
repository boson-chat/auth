// Package settings is the network_settings repository (a single row).
package settings

import (
	"context"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"gorm.io/gorm/clause"
)

// Row holds the stored overrides. A nil field follows the env default.
type Row struct {
	ID                       bool `gorm:"primaryKey"`
	Registration             *string
	RequireEmailVerification *bool
	ChannelCreation          *string
	VoiceChannelCreation     *string
	ChannelAutoRegister      *bool
	ChannelExpiryDays        *int
	GuestAccess              *bool
	GuestVoice               *bool
	UpdatedAt                *time.Time
	UpdatedBy                *string
}

func (Row) TableName() string { return "network_settings" }

type SettingsRepositoryImpl interface {
	// Get returns the row (an empty one if the row is missing).
	Get(ctx context.Context) (*Row, error)
	// GetForUpdate locks the row. Call inside WithTx.
	GetForUpdate(ctx context.Context) (*Row, error)
	Save(ctx context.Context, r *Row) error
}

type SettingsRepository struct {
	db *db.DB
}

func NewSettingsRepository(d *db.DB) SettingsRepositoryImpl {
	return &SettingsRepository{db: d}
}

func (r *SettingsRepository) get(ctx context.Context, lock bool) (*Row, error) {
	var row Row
	q := r.db.Conn(ctx).Where("id")
	if lock {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	err := q.First(&row).Error
	if err := repositories.NotFound(err); err == repositories.ErrNotFound {
		return &Row{ID: true}, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (r *SettingsRepository) Get(ctx context.Context) (*Row, error) { return r.get(ctx, false) }

func (r *SettingsRepository) GetForUpdate(ctx context.Context) (*Row, error) { return r.get(ctx, true) }

func (r *SettingsRepository) Save(ctx context.Context, row *Row) error {
	row.ID = true
	return r.db.Conn(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(row).Error
}
