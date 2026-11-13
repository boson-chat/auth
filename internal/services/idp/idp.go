// Package idp is the extension point for external identity providers
// (OIDC in phase 2, SAML in phase 3). Phase 1 ships the interface, the
// registry and the storage, but no concrete providers.
//
// A provider implementation lives in its own package (idp/oidc, idp/saml)
// and registers a Factory for its kind at wiring time:
//
//	registry.RegisterFactory(identity.KindOIDC, oidc.NewFactory(httpClient))
//
// The registry then builds one IdentityProvider per enabled row in
// identity_providers (config jsonb holds issuer/client id/metadata URL...).
// The HTTP layer will expose:
//
//	GET /v1/sso/{slug}/start     → IdentityProvider.BeginLogin (redirect to IdP)
//	GET|POST /v1/sso/{slug}/callback → CompleteLogin → link or create the user
//	                                  → session.Create(method "oidc:<slug>")
//
// See docs/sso.md for the linking rules.
package idp

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/boson-chat/auth/internal/db/repositories/identity"
	"github.com/boson-chat/auth/internal/logger"
)

// ExternalIdentity is what a provider asserts about the user after login.
type ExternalIdentity struct {
	// Subject is the provider's stable user id (OIDC sub, SAML NameID).
	Subject           string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	DisplayName       string
	// Claims are the raw claims/attributes, stored in user_identities.raw_claims.
	Claims map[string]any
}

// IdentityProvider is one configured external IdP.
type IdentityProvider interface {
	Kind() string
	Slug() string
	DisplayName() string
	// BeginLogin redirects the browser to the IdP. state is an opaque,
	// single-use value the caller has already bound to the browser (cookie);
	// OIDC sends it as state (plus its own nonce/PKCE), SAML as RelayState.
	BeginLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, state string) error
	// CompleteLogin validates the IdP's response (code exchange + ID token
	// verification, or SAML assertion signature/audience/time checks) and
	// returns the asserted identity. The caller has already checked state.
	CompleteLogin(ctx context.Context, r *http.Request) (ExternalIdentity, error)
}

// Factory builds a provider from its stored configuration.
type Factory func(ctx context.Context, p *identity.Provider) (IdentityProvider, error)

// ProviderInfo is the public description of an enabled provider (login buttons).
type ProviderInfo struct {
	Slug        string `json:"slug"`
	Kind        string `json:"kind"`
	DisplayName string `json:"display_name"`
}

// Registry maps slugs to live providers.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
	providers map[string]IdentityProvider
}

func NewRegistry() *Registry {
	return &Registry{factories: map[string]Factory{}, providers: map[string]IdentityProvider{}}
}

// RegisterFactory installs the factory for a kind ("oidc", "saml").
func (r *Registry) RegisterFactory(kind string, f Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[kind] = f
}

// Load (re)builds providers from rows. Rows whose kind has no factory or
// whose config is invalid are skipped with a warning, so one broken IdP
// can't take down password login.
func (r *Registry) Load(ctx context.Context, rows []*identity.Provider) {
	built := map[string]IdentityProvider{}
	r.mu.RLock()
	factories := r.factories
	r.mu.RUnlock()
	for _, row := range rows {
		if !row.Enabled {
			continue
		}
		f, ok := factories[row.Kind]
		if !ok {
			logger.FromCtx(ctx).Warn().Str("slug", row.Slug).Str("kind", row.Kind).Msg("no implementation for identity provider kind; skipping")
			continue
		}
		p, err := f(ctx, row)
		if err != nil {
			logger.FromCtx(ctx).Error().Err(err).Str("slug", row.Slug).Msg("identity provider config invalid; skipping")
			continue
		}
		built[row.Slug] = p
	}
	r.mu.Lock()
	r.providers = built
	r.mu.Unlock()
}

// Get returns the provider for slug.
func (r *Registry) Get(slug string) (IdentityProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[slug]
	if !ok {
		return nil, fmt.Errorf("idp: unknown provider %q", slug)
	}
	return p, nil
}

// List describes the loaded providers, sorted by slug.
func (r *Registry) List() []ProviderInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProviderInfo, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, ProviderInfo{Slug: p.Slug(), Kind: p.Kind(), DisplayName: p.DisplayName()})
	}
	slices.SortFunc(out, func(a, b ProviderInfo) int { return strings.Compare(a.Slug, b.Slug) })
	return out
}

// IdPServiceImpl loads providers from the database into the registry.
type IdPServiceImpl interface {
	Reload(ctx context.Context) error
	Providers() []ProviderInfo
	Provider(slug string) (IdentityProvider, error)
}

type IdPService struct {
	Repository identity.IdentityRepositoryImpl
	Registry   *Registry
}

func NewIdPService(repo identity.IdentityRepositoryImpl, reg *Registry) IdPServiceImpl {
	return &IdPService{Repository: repo, Registry: reg}
}

func (s *IdPService) Reload(ctx context.Context) error {
	rows, err := s.Repository.ListProviders(ctx, true)
	if err != nil {
		return err
	}
	s.Registry.Load(ctx, rows)
	return nil
}

func (s *IdPService) Providers() []ProviderInfo { return s.Registry.List() }

func (s *IdPService) Provider(slug string) (IdentityProvider, error) { return s.Registry.Get(slug) }
