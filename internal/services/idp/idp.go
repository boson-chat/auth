// Package idp defines external identity providers (OIDC, SAML) and the
// registry that holds the live ones.
//
// A provider kind lives in its own package (idp/oidc, idp/saml) and
// registers a Kind at wiring time:
//
//	registry.RegisterKind(identity.KindOIDC, oidc.Kind{HTTPClient: c})
//
// The registry builds one IdentityProvider per enabled identity_providers
// row and reuses it until the row changes (updated_at), so lazily fetched
// discovery documents and IdP metadata stay cached. The sso service drives
// the login flow and the linking rules; see docs/sso.md.
package idp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

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

// LoginRequest is how to send the browser to the IdP, plus values the
// caller must keep (in the encrypted state cookie) and hand back to
// CompleteLogin: the OIDC nonce and PKCE verifier, the SAML request id.
type LoginRequest struct {
	// RedirectURL: send a 302 there (OIDC, SAML HTTP-Redirect binding).
	RedirectURL string
	// PostURL + PostFields: auto-submit a form (SAML HTTP-POST binding).
	PostURL    string
	PostFields map[string]string
	Saved      map[string]string
}

// IdentityProvider is one configured external IdP.
type IdentityProvider interface {
	Kind() string
	Slug() string
	DisplayName() string
	// BeginLogin starts a login. state is the caller's opaque, single-use
	// value already bound to the browser (cookie); OIDC sends it as state,
	// SAML as RelayState.
	BeginLogin(ctx context.Context, state string) (*LoginRequest, error)
	// CompleteLogin validates the IdP's response (code exchange + ID token
	// verification, or SAML signature/audience/time/InResponseTo checks) and
	// returns the asserted identity. The caller has already checked state.
	CompleteLogin(ctx context.Context, r *http.Request, saved map[string]string) (ExternalIdentity, error)
	// Check verifies the configuration against the IdP (discovery + JWKS,
	// or IdP metadata) for the admin "test" button.
	Check(ctx context.Context) (map[string]any, error)
}

// SPMetadata is implemented by providers that publish SAML SP metadata.
type SPMetadata interface {
	Metadata() ([]byte, error)
}

// BuildContext is what a Kind needs besides the stored row.
type BuildContext struct {
	ClientSecret string
	SPKey        *rsa.PrivateKey
	SPCert       *x509.Certificate
	// Our endpoints for this provider.
	CallbackURL string // OIDC redirect_uri
	ACSURL      string // SAML assertion consumer service
	MetadataURL string // SAML SP metadata (and default SP entity id)
}

// Kind implements one provider type.
type Kind interface {
	// Normalize validates a provider's config (without secrets) and returns
	// the form to store.
	Normalize(cfg map[string]any) (map[string]any, error)
	// Build makes a provider. It must not do network I/O; fetch discovery
	// documents or metadata lazily.
	Build(p *identity.Provider, bc BuildContext) (IdentityProvider, error)
}

// ProviderInfo is the public description of an enabled provider (login buttons).
type ProviderInfo struct {
	Slug        string `json:"slug"`
	Kind        string `json:"kind"`
	DisplayName string `json:"display_name"`
	StartURL    string `json:"start_url"`
}

type entry struct {
	updatedAt time.Time
	provider  IdentityProvider
}

// Registry maps slugs to live providers.
type Registry struct {
	mu        sync.RWMutex
	kinds     map[string]Kind
	providers map[string]entry
}

func NewRegistry() *Registry {
	return &Registry{kinds: map[string]Kind{}, providers: map[string]entry{}}
}

// RegisterKind installs the implementation of a kind ("oidc", "saml").
func (r *Registry) RegisterKind(name string, k Kind) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kinds[name] = k
}

// Kind returns the implementation of a kind.
func (r *Registry) Kind(name string) (Kind, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.kinds[name]
	return k, ok
}

// Load (re)builds providers from rows, reusing unchanged ones. Rows whose
// kind is unknown or whose config is invalid are skipped with a log line,
// so one broken IdP can't take down the others or password login.
func (r *Registry) Load(ctx context.Context, rows []*identity.Provider, bc func(*identity.Provider) (BuildContext, error)) {
	r.mu.RLock()
	old := r.providers
	kinds := r.kinds
	r.mu.RUnlock()
	built := map[string]entry{}
	for _, row := range rows {
		if !row.Enabled {
			continue
		}
		if e, ok := old[row.Slug]; ok && e.updatedAt.Equal(row.UpdatedAt) && e.provider.Kind() == row.Kind {
			built[row.Slug] = e
			continue
		}
		k, ok := kinds[row.Kind]
		if !ok {
			logger.FromCtx(ctx).Warn().Str("slug", row.Slug).Str("kind", row.Kind).Msg("no implementation for identity provider kind; skipping")
			continue
		}
		c, err := bc(row)
		if err == nil {
			var p IdentityProvider
			if p, err = k.Build(row, c); err == nil {
				built[row.Slug] = entry{updatedAt: row.UpdatedAt, provider: p}
				continue
			}
		}
		logger.FromCtx(ctx).Error().Err(err).Str("slug", row.Slug).Msg("identity provider config invalid; skipping")
	}
	r.mu.Lock()
	r.providers = built
	r.mu.Unlock()
}

// Get returns the provider for slug.
func (r *Registry) Get(slug string) (IdentityProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.providers[slug]
	if !ok {
		return nil, fmt.Errorf("idp: unknown provider %q", slug)
	}
	return e.provider, nil
}

// List describes the loaded providers, sorted by slug (StartURL unset).
func (r *Registry) List() []ProviderInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProviderInfo, 0, len(r.providers))
	for _, e := range r.providers {
		p := e.provider
		out = append(out, ProviderInfo{Slug: p.Slug(), Kind: p.Kind(), DisplayName: p.DisplayName()})
	}
	slices.SortFunc(out, func(a, b ProviderInfo) int { return strings.Compare(a.Slug, b.Slug) })
	return out
}
