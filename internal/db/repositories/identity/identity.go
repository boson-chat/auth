// Package identity is the repository for identity_providers and
// user_identities (SSO links). Phase 1 ships no concrete providers.
package identity

import (
	"context"
	"errors"
	"time"

	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
)

const (
	KindOIDC = "oidc"
	KindSAML = "saml"
)

var ErrSlugTaken = errors.New("provider slug taken")

type Provider struct {
	ID          string
	Kind        string
	Slug        string
	DisplayName string
	// Kind-specific settings (issuer, client id, metadata URL, ...). Secrets
	// placed here should be references (env var names), not values.
	Config      repositories.JSONB
	Enabled     bool
	AllowSignup bool
	// Link to an existing account when the IdP asserts a verified email that
	// matches. Only enable for IdPs you control.
	TrustEmail bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (Provider) TableName() string { return "identity_providers" }

type UserIdentity struct {
	ID          string
	UserID      string
	ProviderID  string
	Subject     string
	Email       *string
	RawClaims   repositories.JSONB
	CreatedAt   time.Time
	LastLoginAt *time.Time
}

func (UserIdentity) TableName() string { return "user_identities" }

type IdentityRepositoryImpl interface {
	CreateProvider(ctx context.Context, p *Provider) error
	FindProviderBySlug(ctx context.Context, slug string) (*Provider, error)
	ListProviders(ctx context.Context, enabledOnly bool) ([]*Provider, error)

	CreateIdentity(ctx context.Context, i *UserIdentity) error
	FindIdentity(ctx context.Context, providerID, subject string) (*UserIdentity, error)
	ListIdentitiesByUser(ctx context.Context, userID string) ([]*UserIdentity, error)
	TouchIdentity(ctx context.Context, id string, at time.Time, email *string, claims repositories.JSONB) error
}

type IdentityRepository struct {
	db *db.DB
}

func NewIdentityRepository(d *db.DB) IdentityRepositoryImpl {
	return &IdentityRepository{db: d}
}

func (r *IdentityRepository) CreateProvider(ctx context.Context, p *Provider) error {
	err := r.db.Conn(ctx).Create(p).Error
	if repositories.UniqueViolation(err) != "" {
		return ErrSlugTaken
	}
	return err
}

func (r *IdentityRepository) FindProviderBySlug(ctx context.Context, slug string) (*Provider, error) {
	var p Provider
	if err := r.db.Conn(ctx).Where("slug = ?", slug).First(&p).Error; err != nil {
		return nil, repositories.NotFound(err)
	}
	return &p, nil
}

func (r *IdentityRepository) ListProviders(ctx context.Context, enabledOnly bool) ([]*Provider, error) {
	q := r.db.Conn(ctx).Order("slug")
	if enabledOnly {
		q = q.Where("enabled")
	}
	var out []*Provider
	return out, q.Find(&out).Error
}

func (r *IdentityRepository) CreateIdentity(ctx context.Context, i *UserIdentity) error {
	return r.db.Conn(ctx).Create(i).Error
}

func (r *IdentityRepository) FindIdentity(ctx context.Context, providerID, subject string) (*UserIdentity, error) {
	if subject == "" {
		return nil, repositories.ErrNotFound
	}
	var i UserIdentity
	err := r.db.Conn(ctx).Where("provider_id = ? AND subject = ?", providerID, subject).First(&i).Error
	if err != nil {
		return nil, repositories.NotFound(err)
	}
	return &i, nil
}

func (r *IdentityRepository) ListIdentitiesByUser(ctx context.Context, userID string) ([]*UserIdentity, error) {
	var out []*UserIdentity
	return out, r.db.Conn(ctx).Where("user_id = ?", userID).Order("created_at").Find(&out).Error
}

func (r *IdentityRepository) TouchIdentity(ctx context.Context, id string, at time.Time, email *string, claims repositories.JSONB) error {
	return r.db.Conn(ctx).Model(&UserIdentity{}).Where("id = ?", id).
		Updates(map[string]any{"last_login_at": at, "email": email, "raw_claims": claims}).Error
}
