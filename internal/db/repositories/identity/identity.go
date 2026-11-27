// Package identity is the repository for identity_providers and
// user_identities (SSO links).
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

var (
	ErrSlugTaken     = errors.New("provider slug taken")
	ErrIdentityTaken = errors.New("identity already linked")
)

type Provider struct {
	ID          string
	Kind        string
	Slug        string
	DisplayName string
	// Kind-specific, non-secret settings (issuer, client id, metadata, ...).
	Config      repositories.JSONB
	Enabled     bool
	AllowSignup bool
	// Link to an existing account when the IdP asserts a verified email that
	// matches. Only enable for IdPs you control.
	TrustEmail bool
	// Create accounts through this provider even when registration is closed
	// or invite-only (AllowSignup must also be on).
	SignupWhenClosed bool
	// Encrypted secrets (keycrypt, aad = "<column>:<id>").
	ClientSecretEnc []byte
	SPKeyEnc        []byte
	SPCert          string
	CreatedAt       time.Time
	UpdatedAt       time.Time
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

// IdentityView is an identity with its provider's public fields.
type IdentityView struct {
	UserIdentity        `gorm:"embedded"`
	ProviderSlug        string
	ProviderKind        string
	ProviderDisplayName string
}

type IdentityRepositoryImpl interface {
	CreateProvider(ctx context.Context, p *Provider) error
	UpdateProvider(ctx context.Context, p *Provider) error
	DeleteProvider(ctx context.Context, id string) error
	FindProviderByID(ctx context.Context, id string) (*Provider, error)
	FindProviderBySlug(ctx context.Context, slug string) (*Provider, error)
	ListProviders(ctx context.Context, enabledOnly bool) ([]*Provider, error)

	CreateIdentity(ctx context.Context, i *UserIdentity) error
	FindIdentity(ctx context.Context, providerID, subject string) (*UserIdentity, error)
	ListIdentitiesByUser(ctx context.Context, userID string) ([]*IdentityView, error)
	TouchIdentity(ctx context.Context, id string, at time.Time, email *string, claims repositories.JSONB) error
	// DeleteIdentity removes userID's identity id (ErrNotFound if not theirs).
	DeleteIdentity(ctx context.Context, userID, id string) error
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

func (r *IdentityRepository) UpdateProvider(ctx context.Context, p *Provider) error {
	res := r.db.Conn(ctx).Model(&Provider{}).Where("id = ?", p.ID).Updates(map[string]any{
		"slug": p.Slug, "display_name": p.DisplayName, "config": p.Config, "enabled": p.Enabled,
		"allow_signup": p.AllowSignup, "trust_email": p.TrustEmail, "signup_when_closed": p.SignupWhenClosed, "client_secret_enc": p.ClientSecretEnc,
		"sp_key_enc": p.SPKeyEnc, "sp_cert": p.SPCert, "updated_at": p.UpdatedAt,
	})
	if repositories.UniqueViolation(res.Error) != "" {
		return ErrSlugTaken
	}
	if res.Error == nil && res.RowsAffected == 0 {
		return repositories.ErrNotFound
	}
	return res.Error
}

func (r *IdentityRepository) DeleteProvider(ctx context.Context, id string) error {
	res := r.db.Conn(ctx).Where("id = ?", id).Delete(&Provider{})
	if res.Error == nil && res.RowsAffected == 0 {
		return repositories.ErrNotFound
	}
	return res.Error
}

func (r *IdentityRepository) findProvider(ctx context.Context, col, v string) (*Provider, error) {
	if v == "" {
		return nil, repositories.ErrNotFound
	}
	var p Provider
	if err := r.db.Conn(ctx).Where(col+" = ?", v).First(&p).Error; err != nil {
		return nil, repositories.NotFound(err)
	}
	return &p, nil
}

func (r *IdentityRepository) FindProviderByID(ctx context.Context, id string) (*Provider, error) {
	return r.findProvider(ctx, "id", id)
}

func (r *IdentityRepository) FindProviderBySlug(ctx context.Context, slug string) (*Provider, error) {
	return r.findProvider(ctx, "slug", slug)
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
	err := r.db.Conn(ctx).Create(i).Error
	if repositories.UniqueViolation(err) != "" {
		return ErrIdentityTaken
	}
	return err
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

func (r *IdentityRepository) ListIdentitiesByUser(ctx context.Context, userID string) ([]*IdentityView, error) {
	var out []*IdentityView
	err := r.db.Conn(ctx).Table("user_identities AS i").
		Select("i.*, p.slug AS provider_slug, p.kind AS provider_kind, p.display_name AS provider_display_name").
		Joins("JOIN identity_providers p ON p.id = i.provider_id").
		Where("i.user_id = ?", userID).Order("i.created_at, i.id").Scan(&out).Error
	return out, err
}

func (r *IdentityRepository) TouchIdentity(ctx context.Context, id string, at time.Time, email *string, claims repositories.JSONB) error {
	return r.db.Conn(ctx).Model(&UserIdentity{}).Where("id = ?", id).
		Updates(map[string]any{"last_login_at": at, "email": email, "raw_claims": claims}).Error
}

func (r *IdentityRepository) DeleteIdentity(ctx context.Context, userID, id string) error {
	res := r.db.Conn(ctx).Where("id = ? AND user_id = ?", id, userID).Delete(&UserIdentity{})
	if res.Error == nil && res.RowsAffected == 0 {
		return repositories.ErrNotFound
	}
	return res.Error
}
