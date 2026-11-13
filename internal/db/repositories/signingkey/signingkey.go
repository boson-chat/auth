// Package signingkey is the signing_keys repository.
package signingkey

import (
	"context"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
)

type SigningKey struct {
	KID           string `gorm:"column:kid;primaryKey"`
	Alg           string
	PrivateKeyEnc []byte
	PublicJWK     repositories.JSONB `gorm:"column:public_jwk"`
	CreatedAt     time.Time
	ActivatedAt   time.Time
	RetiredAt     *time.Time
}

func (SigningKey) TableName() string { return "signing_keys" }

// rotationLockID is the pg_advisory_xact_lock key serialising key creation
// across replicas ("boson-ke" as an int64).
const rotationLockID int64 = 0x626f736f6e2d6b65

type SigningKeyRepositoryImpl interface {
	// LockRotation takes a transaction-scoped advisory lock. Call inside WithTx.
	LockRotation(ctx context.Context) error
	Create(ctx context.Context, k *SigningKey) error
	// ListUsable returns keys not retired before retiredAfter, oldest first.
	ListUsable(ctx context.Context, retiredAfter time.Time) ([]*SigningKey, error)
	ListAll(ctx context.Context) ([]*SigningKey, error)
	Retire(ctx context.Context, kid string, at time.Time) error
}

type SigningKeyRepository struct {
	db *db.DB
}

func NewSigningKeyRepository(d *db.DB) SigningKeyRepositoryImpl {
	return &SigningKeyRepository{db: d}
}

func (r *SigningKeyRepository) LockRotation(ctx context.Context) error {
	return r.db.Conn(ctx).Exec("SELECT pg_advisory_xact_lock(?)", rotationLockID).Error
}

func (r *SigningKeyRepository) Create(ctx context.Context, k *SigningKey) error {
	return r.db.Conn(ctx).Create(k).Error
}

func (r *SigningKeyRepository) ListUsable(ctx context.Context, retiredAfter time.Time) ([]*SigningKey, error) {
	var out []*SigningKey
	err := r.db.Conn(ctx).Where("retired_at IS NULL OR retired_at > ?", retiredAfter).
		Order("activated_at ASC, kid ASC").Find(&out).Error
	return out, err
}

func (r *SigningKeyRepository) ListAll(ctx context.Context) ([]*SigningKey, error) {
	var out []*SigningKey
	err := r.db.Conn(ctx).Order("activated_at ASC, kid ASC").Find(&out).Error
	return out, err
}

func (r *SigningKeyRepository) Retire(ctx context.Context, kid string, at time.Time) error {
	res := r.db.Conn(ctx).Model(&SigningKey{}).Where("kid = ?", kid).Update("retired_at", at)
	if res.Error == nil && res.RowsAffected == 0 {
		return repositories.ErrNotFound
	}
	return res.Error
}
