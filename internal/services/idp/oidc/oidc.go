// Package oidc is the OpenID Connect provider kind (authorization code flow
// with PKCE and nonce), for Google, Authentik, Zitadel, Keycloak, Okta,
// Entra ID, Dex and any other spec-compliant issuer.
package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories/identity"
	"github.com/boson-chat/auth/internal/opaque"
	"github.com/boson-chat/auth/internal/services/idp"
	"github.com/boson-chat/auth/internal/textutil"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	savedNonce    = "nonce"
	savedVerifier = "pkce"
	// retryAfter throttles discovery retries while an issuer is down.
	retryAfter = 5 * time.Second
)

var defaultScopes = []string{gooidc.ScopeOpenID, "email", "profile"}

// ErrIdP is returned when the IdP reports an error on the callback
// (e.g. the user cancelled). Code is the OAuth error code.
type ErrIdP struct{ Code, Description string }

func (e *ErrIdP) Error() string { return "oidc: idp returned " + e.Code + ": " + e.Description }

// Config is the stored (non-secret) configuration.
type Config struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	// Claim names; empty = the defaults (preferred_username/nickname, email, name).
	UsernameClaim    string `json:"username_claim,omitempty"`
	EmailClaim       string `json:"email_claim,omitempty"`
	DisplayNameClaim string `json:"display_name_claim,omitempty"`
}

// Kind builds OIDC providers.
type Kind struct {
	HTTPClient *http.Client
	// AllowHTTP accepts http:// issuers on any host (dev only). Loopback
	// issuers (127.0.0.1, ::1, localhost) are always accepted.
	AllowHTTP bool
}

func parseConfig(m map[string]any) (Config, error) {
	var c Config
	b, err := json.Marshal(m)
	if err != nil {
		return c, apperr.Invalid("config is not valid JSON")
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, apperr.Invalid("oidc config: " + err.Error())
	}
	return c, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (k Kind) Normalize(m map[string]any) (map[string]any, error) {
	c, err := parseConfig(m)
	if err != nil {
		return nil, err
	}
	c.Issuer = strings.TrimSpace(c.Issuer)
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || !textutil.Storable(c.Issuer) || len(c.Issuer) > 512 {
		return nil, apperr.Invalid("issuer must be an absolute URL")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && (k.AllowHTTP || loopback(u.Hostname())):
	default:
		return nil, apperr.Invalid("issuer must use https")
	}
	c.ClientID = strings.TrimSpace(c.ClientID)
	if c.ClientID == "" || len(c.ClientID) > 512 || !textutil.Storable(c.ClientID) {
		return nil, apperr.Invalid("client_id is required")
	}
	if len(c.Scopes) == 0 {
		c.Scopes = slices.Clone(defaultScopes)
	}
	if !slices.Contains(c.Scopes, gooidc.ScopeOpenID) {
		c.Scopes = append([]string{gooidc.ScopeOpenID}, c.Scopes...)
	}
	if len(c.Scopes) > 20 {
		return nil, apperr.Invalid("at most 20 scopes")
	}
	for _, s := range append(slices.Clone(c.Scopes), c.UsernameClaim, c.EmailClaim, c.DisplayNameClaim) {
		if len(s) > 128 || !textutil.Storable(s) || strings.ContainsAny(s, " \t\r\n") {
			return nil, apperr.Invalid("scopes and claim names must be single words")
		}
	}
	out := map[string]any{}
	b, _ := json.Marshal(c)
	_ = json.Unmarshal(b, &out)
	return out, nil
}

func (k Kind) Build(p *identity.Provider, bc idp.BuildContext) (idp.IdentityProvider, error) {
	c, err := parseConfig(p.Config)
	if err != nil {
		return nil, err
	}
	if c.Issuer == "" || c.ClientID == "" {
		return nil, errors.New("oidc: issuer and client_id are required")
	}
	client := k.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	return &Provider{slug: p.Slug, displayName: p.DisplayName, cfg: c, secret: bc.ClientSecret, redirect: bc.CallbackURL, client: client}, nil
}

// Provider is one OIDC issuer. Discovery runs on first use.
type Provider struct {
	slug, displayName string
	cfg               Config
	secret, redirect  string
	client            *http.Client

	mu       sync.Mutex
	op       *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth    *oauth2.Config
	failedAt time.Time
	lastErr  error
}

func (p *Provider) Kind() string        { return identity.KindOIDC }
func (p *Provider) Slug() string        { return p.slug }
func (p *Provider) DisplayName() string { return p.displayName }

// clientCtx carries our HTTP client into go-oidc and x/oauth2.
func (p *Provider) clientCtx(ctx context.Context) context.Context {
	return gooidc.ClientContext(ctx, p.client)
}

func (p *Provider) init(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.op != nil {
		return nil
	}
	if !p.failedAt.IsZero() && time.Since(p.failedAt) < retryAfter {
		return p.lastErr
	}
	// go-oidc keeps only the HTTP client from this context for later JWKS
	// fetches, so the request's cancellation doesn't leak into them.
	op, err := gooidc.NewProvider(p.clientCtx(ctx), p.cfg.Issuer)
	if err != nil {
		p.failedAt, p.lastErr = time.Now(), fmt.Errorf("oidc discovery for %s: %w", p.cfg.Issuer, err)
		return p.lastErr
	}
	p.op = op
	p.verifier = op.Verifier(&gooidc.Config{ClientID: p.cfg.ClientID})
	p.oauth = &oauth2.Config{
		ClientID: p.cfg.ClientID, ClientSecret: p.secret, Endpoint: op.Endpoint(),
		RedirectURL: p.redirect, Scopes: p.cfg.Scopes,
	}
	return nil
}

func (p *Provider) BeginLogin(ctx context.Context, state string) (*idp.LoginRequest, error) {
	if err := p.init(ctx); err != nil {
		return nil, err
	}
	nonce := opaque.New("")
	verifier := oauth2.GenerateVerifier()
	return &idp.LoginRequest{
		RedirectURL: p.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), gooidc.Nonce(nonce)),
		Saved:       map[string]string{savedNonce: nonce, savedVerifier: verifier},
	}, nil
}

func (p *Provider) CompleteLogin(ctx context.Context, r *http.Request, saved map[string]string) (idp.ExternalIdentity, error) {
	var x idp.ExternalIdentity
	q := r.URL.Query()
	if code := q.Get("error"); code != "" {
		return x, &ErrIdP{Code: textutil.Clean(code, 64), Description: textutil.Clean(q.Get("error_description"), 256)}
	}
	code := q.Get("code")
	if code == "" || saved[savedNonce] == "" || saved[savedVerifier] == "" {
		return x, errors.New("oidc: missing code or saved state")
	}
	if err := p.init(ctx); err != nil {
		return x, err
	}
	cctx := p.clientCtx(ctx)
	tok, err := p.oauth.Exchange(cctx, code, oauth2.VerifierOption(saved[savedVerifier]))
	if err != nil {
		return x, fmt.Errorf("oidc: code exchange: %w", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return x, errors.New("oidc: token response has no id_token")
	}
	idt, err := p.verifier.Verify(cctx, rawID)
	if err != nil {
		return x, fmt.Errorf("oidc: id_token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(saved[savedNonce])) != 1 {
		return x, errors.New("oidc: nonce mismatch")
	}
	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		return x, fmt.Errorf("oidc: claims: %w", err)
	}
	// Some IdPs (Zitadel by default, Okta org servers) leave profile and
	// email claims out of the ID token; fill them from UserInfo.
	if _, ok := claims[p.claim(p.cfg.EmailClaim, "email")]; !ok && p.op.UserInfoEndpoint() != "" {
		if ui, err := p.op.UserInfo(cctx, oauth2.StaticTokenSource(tok)); err == nil && ui.Subject == idt.Subject {
			extra := map[string]any{}
			if ui.Claims(&extra) == nil {
				for k, v := range extra {
					if _, exists := claims[k]; !exists {
						claims[k] = v
					}
				}
			}
		}
	}
	return p.identityFrom(idt.Subject, claims), nil
}

func (p *Provider) claim(configured, def string) string {
	if configured != "" {
		return configured
	}
	return def
}

func str(claims map[string]any, name string) string {
	s, _ := claims[name].(string)
	return strings.TrimSpace(s)
}

// truthy accepts true and "true" (some IdPs send email_verified as a string).
func truthy(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	}
	return false
}

func (p *Provider) identityFrom(sub string, claims map[string]any) idp.ExternalIdentity {
	x := idp.ExternalIdentity{
		Subject:       sub,
		Email:         str(claims, p.claim(p.cfg.EmailClaim, "email")),
		EmailVerified: truthy(claims["email_verified"]),
		DisplayName:   str(claims, p.claim(p.cfg.DisplayNameClaim, "name")),
		Claims:        claims,
	}
	for _, c := range []string{p.cfg.UsernameClaim, "preferred_username", "nickname"} {
		if c != "" {
			if v := str(claims, c); v != "" {
				x.PreferredUsername = v
				break
			}
		}
	}
	return x
}

// Check runs discovery and fetches the JWKS.
func (p *Provider) Check(ctx context.Context) (map[string]any, error) {
	if err := p.init(ctx); err != nil {
		return map[string]any{"issuer": p.cfg.Issuer}, err
	}
	var meta struct {
		JWKSURI          string   `json:"jwks_uri"`
		UserInfo         string   `json:"userinfo_endpoint"`
		Scopes           []string `json:"scopes_supported"`
		ChallengeMethods []string `json:"code_challenge_methods_supported"`
	}
	_ = p.op.Claims(&meta)
	details := map[string]any{
		"issuer":                           p.cfg.Issuer,
		"authorization_endpoint":           p.op.Endpoint().AuthURL,
		"token_endpoint":                   p.op.Endpoint().TokenURL,
		"userinfo_endpoint":                meta.UserInfo,
		"jwks_uri":                         meta.JWKSURI,
		"scopes_supported":                 meta.Scopes,
		"code_challenge_methods_supported": meta.ChallengeMethods,
		"redirect_uri":                     p.redirect,
	}
	if meta.JWKSURI == "" {
		return details, errors.New("discovery document has no jwks_uri")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.JWKSURI, nil)
	if err != nil {
		return details, err
	}
	res, err := p.client.Do(req)
	if err != nil {
		return details, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return details, fmt.Errorf("fetching JWKS: HTTP %d", res.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, res.Body, 1<<20)).Decode(&set); err != nil {
		return details, fmt.Errorf("JWKS is not valid JSON: %w", err)
	}
	if len(set.Keys) == 0 {
		return details, errors.New("JWKS has no keys")
	}
	details["jwks_keys"] = len(set.Keys)
	if len(meta.ChallengeMethods) > 0 && !slices.Contains(meta.ChallengeMethods, "S256") {
		details["warning"] = "issuer does not advertise PKCE S256"
	}
	return details, nil
}
