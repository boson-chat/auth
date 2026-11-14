// Package saml is the SAML 2.0 service-provider kind (crewjam/saml): SP
// metadata, SP-initiated login (HTTP-Redirect or HTTP-POST binding) and
// assertion validation at the ACS (HTTP-POST binding). IdP-initiated logins
// are refused: every response must answer a request we made.
package saml

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories/identity"
	"github.com/boson-chat/auth/internal/services/idp"
	"github.com/boson-chat/auth/internal/textutil"
	crewsaml "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	savedRequestID = "request_id"
	// metadataRefresh is how often IdP metadata fetched by URL is reloaded.
	metadataRefresh = 24 * time.Hour
	retryAfter      = 5 * time.Second
	maxMetadataXML  = 1 << 20
)

// AttributeMap names the assertion attributes (Name or FriendlyName) that
// carry the user's email, username and display name. Empty = common defaults.
type AttributeMap struct {
	Email       string `json:"email,omitempty"`
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

// Config is the stored configuration. Exactly one of IDPMetadataURL and
// IDPMetadataXML is set.
type Config struct {
	IDPMetadataURL string `json:"idp_metadata_url,omitempty"`
	IDPMetadataXML string `json:"idp_metadata_xml,omitempty"`
	// EntityID overrides the SP entity id (default: the SP metadata URL).
	EntityID     string       `json:"entity_id,omitempty"`
	AttributeMap AttributeMap `json:"attribute_map"`
	// NameIDFormat to request: persistent | email | unspecified | a URN.
	// Empty = don't ask for one (the IdP's default).
	NameIDFormat string `json:"name_id_format,omitempty"`
	// SignRequests signs AuthnRequests with the SP key.
	SignRequests bool `json:"sign_requests,omitempty"`
}

// Defaults cover Okta, Entra ID, ADFS, Authentik, Keycloak and LDAP-style OIDs.
var (
	defaultEmail = []string{"email", "mail", "Email", "emailaddress",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3"}
	defaultUsername = []string{"username", "preferred_username", "uid", "nickname", "urn:oid:0.9.2342.19200300.100.1.1"}
	defaultDisplay  = []string{"displayName", "display_name", "name", "cn",
		"http://schemas.microsoft.com/identity/claims/displayname", "urn:oid:2.16.840.1.113730.3.1.241", "urn:oid:2.5.4.3"}
)

// Kind builds SAML providers.
type Kind struct {
	HTTPClient *http.Client
	// AllowHTTP accepts http:// metadata URLs on any host (dev only).
	AllowHTTP bool
}

func parseConfig(m map[string]any) (Config, error) {
	var c Config
	b, err := json.Marshal(m)
	if err != nil {
		return c, apperr.Invalid("config is not valid JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, apperr.Invalid("saml config: " + err.Error())
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

func nameIDFormat(v string) (string, error) {
	switch v {
	case "":
		return "", nil
	case "persistent":
		return string(crewsaml.PersistentNameIDFormat), nil
	case "email":
		return string(crewsaml.EmailAddressNameIDFormat), nil
	case "unspecified":
		return string(crewsaml.UnspecifiedNameIDFormat), nil
	case string(crewsaml.TransientNameIDFormat), "transient":
		return "", apperr.Invalid("transient NameIDs change on every login and can't identify an account")
	}
	if strings.HasPrefix(v, "urn:") && len(v) < 256 && textutil.Storable(v) {
		return v, nil
	}
	return "", apperr.Invalid("name_id_format must be persistent, email, unspecified or a URN")
}

// ParseIdPMetadata parses IdP metadata XML and checks it describes an IdP.
func ParseIdPMetadata(b []byte) (*crewsaml.EntityDescriptor, error) {
	md, err := samlsp.ParseMetadata(b)
	if err != nil {
		return nil, fmt.Errorf("idp metadata: %w", err)
	}
	if len(md.IDPSSODescriptors) == 0 {
		return nil, errors.New("idp metadata has no IDPSSODescriptor")
	}
	return md, nil
}

func (k Kind) Normalize(m map[string]any) (map[string]any, error) {
	c, err := parseConfig(m)
	if err != nil {
		return nil, err
	}
	c.IDPMetadataURL = strings.TrimSpace(c.IDPMetadataURL)
	c.IDPMetadataXML = strings.TrimSpace(c.IDPMetadataXML)
	switch {
	case c.IDPMetadataURL != "" && c.IDPMetadataXML != "":
		return nil, apperr.Invalid("give idp_metadata_url or idp_metadata_xml, not both")
	case c.IDPMetadataURL != "":
		u, err := url.Parse(c.IDPMetadataURL)
		if err != nil || u.Host == "" || len(c.IDPMetadataURL) > 1024 || !textutil.Storable(c.IDPMetadataURL) {
			return nil, apperr.Invalid("idp_metadata_url must be an absolute URL")
		}
		if u.Scheme != "https" && !(u.Scheme == "http" && (k.AllowHTTP || loopback(u.Hostname()))) {
			return nil, apperr.Invalid("idp_metadata_url must use https")
		}
	case c.IDPMetadataXML != "":
		if len(c.IDPMetadataXML) > maxMetadataXML {
			return nil, apperr.Invalid("idp_metadata_xml is too large")
		}
		if _, err := ParseIdPMetadata([]byte(c.IDPMetadataXML)); err != nil {
			return nil, apperr.Invalid(err.Error())
		}
	default:
		return nil, apperr.Invalid("idp_metadata_url or idp_metadata_xml is required")
	}
	if c.NameIDFormat, err = nameIDFormat(c.NameIDFormat); err != nil {
		return nil, err
	}
	for _, s := range []string{c.EntityID, c.AttributeMap.Email, c.AttributeMap.Username, c.AttributeMap.DisplayName} {
		if len(s) > 512 || !textutil.Storable(s) {
			return nil, apperr.Invalid("entity_id and attribute names must be at most 512 bytes")
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
	if bc.SPKey == nil || bc.SPCert == nil {
		return nil, errors.New("saml: provider has no SP key")
	}
	acs, err := url.Parse(bc.ACSURL)
	if err != nil {
		return nil, err
	}
	md, err := url.Parse(bc.MetadataURL)
	if err != nil {
		return nil, err
	}
	client := k.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	sp := crewsaml.ServiceProvider{
		EntityID:          c.EntityID,
		Key:               bc.SPKey,
		Certificate:       bc.SPCert,
		HTTPClient:        client,
		MetadataURL:       *md,
		AcsURL:            *acs,
		AuthnNameIDFormat: crewsaml.NameIDFormat(c.NameIDFormat),
		// We only accept responses to our own requests.
		AllowIDPInitiated:                false,
		AssertionConsumerServiceBindings: []string{crewsaml.HTTPPostBinding},
	}
	if c.NameIDFormat == "" {
		sp.AuthnNameIDFormat = ""
	}
	if c.SignRequests {
		sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	}
	return &Provider{slug: p.Slug, displayName: p.DisplayName, cfg: c, base: sp, client: client}, nil
}

// Provider is one SAML IdP. IdP metadata is parsed (or fetched) on first use.
type Provider struct {
	slug, displayName string
	cfg               Config
	base              crewsaml.ServiceProvider
	client            *http.Client

	mu       sync.Mutex
	sp       *crewsaml.ServiceProvider
	loadedAt time.Time
	failedAt time.Time
	lastErr  error
}

func (p *Provider) Kind() string        { return identity.KindSAML }
func (p *Provider) Slug() string        { return p.slug }
func (p *Provider) DisplayName() string { return p.displayName }

// Metadata returns the SP metadata XML (doesn't need the IdP).
func (p *Provider) Metadata() ([]byte, error) {
	sp := p.base
	return xml.MarshalIndent(sp.Metadata(), "", "  ")
}

// SPEntityID is the entity id IdPs must use as audience.
func (p *Provider) SPEntityID() string {
	if p.base.EntityID != "" {
		return p.base.EntityID
	}
	return p.base.MetadataURL.String()
}

func (p *Provider) serviceProvider(ctx context.Context) (*crewsaml.ServiceProvider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fresh := p.sp != nil && (p.cfg.IDPMetadataXML != "" || time.Since(p.loadedAt) < metadataRefresh)
	if fresh {
		return p.sp, nil
	}
	if !p.failedAt.IsZero() && time.Since(p.failedAt) < retryAfter {
		if p.sp != nil {
			return p.sp, nil
		}
		return nil, p.lastErr
	}
	var md *crewsaml.EntityDescriptor
	var err error
	if p.cfg.IDPMetadataXML != "" {
		md, err = ParseIdPMetadata([]byte(p.cfg.IDPMetadataXML))
	} else {
		var u *url.URL
		if u, err = url.Parse(p.cfg.IDPMetadataURL); err == nil {
			if md, err = samlsp.FetchMetadata(ctx, p.client, *u); err == nil && len(md.IDPSSODescriptors) == 0 {
				err = errors.New("idp metadata has no IDPSSODescriptor")
			}
		}
	}
	if err != nil {
		p.failedAt, p.lastErr = time.Now(), fmt.Errorf("saml metadata: %w", err)
		if p.sp != nil { // keep using the last good metadata
			return p.sp, nil
		}
		return nil, p.lastErr
	}
	sp := p.base
	sp.IDPMetadata = md
	p.sp, p.loadedAt, p.failedAt = &sp, time.Now(), time.Time{}
	return p.sp, nil
}

func (p *Provider) BeginLogin(ctx context.Context, state string) (*idp.LoginRequest, error) {
	sp, err := p.serviceProvider(ctx)
	if err != nil {
		return nil, err
	}
	if loc := sp.GetSSOBindingLocation(crewsaml.HTTPRedirectBinding); loc != "" {
		req, err := sp.MakeAuthenticationRequest(loc, crewsaml.HTTPRedirectBinding, crewsaml.HTTPPostBinding)
		if err != nil {
			return nil, err
		}
		u, err := req.Redirect(state, sp)
		if err != nil {
			return nil, err
		}
		return &idp.LoginRequest{RedirectURL: u.String(), Saved: map[string]string{savedRequestID: req.ID}}, nil
	}
	loc := sp.GetSSOBindingLocation(crewsaml.HTTPPostBinding)
	if loc == "" {
		return nil, errors.New("saml: idp has no HTTP-Redirect or HTTP-POST SSO endpoint")
	}
	req, err := sp.MakeAuthenticationRequest(loc, crewsaml.HTTPPostBinding, crewsaml.HTTPPostBinding)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	buf, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	return &idp.LoginRequest{
		PostURL:    req.Destination,
		PostFields: map[string]string{"SAMLRequest": base64.StdEncoding.EncodeToString(buf), "RelayState": state},
		Saved:      map[string]string{savedRequestID: req.ID},
	}, nil
}

// CompleteLogin validates the POSTed SAMLResponse. r.PostForm must be parsed.
func (p *Provider) CompleteLogin(ctx context.Context, r *http.Request, saved map[string]string) (idp.ExternalIdentity, error) {
	var x idp.ExternalIdentity
	if saved[savedRequestID] == "" {
		return x, errors.New("saml: no request id in state")
	}
	sp, err := p.serviceProvider(ctx)
	if err != nil {
		return x, err
	}
	a, err := sp.ParseResponse(r, []string{saved[savedRequestID]})
	if err != nil {
		var ire *crewsaml.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			return x, fmt.Errorf("saml: invalid response: %w", ire.PrivateErr)
		}
		return x, fmt.Errorf("saml: invalid response: %w", err)
	}
	if a.Subject == nil || a.Subject.NameID == nil || strings.TrimSpace(a.Subject.NameID.Value) == "" {
		return x, errors.New("saml: assertion has no NameID")
	}
	nid := a.Subject.NameID
	if nid.Format == string(crewsaml.TransientNameIDFormat) {
		return x, errors.New("saml: transient NameID can't identify an account; configure a persistent or email NameID at the IdP")
	}
	attrs := map[string][]string{}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			for _, v := range at.Values {
				attrs[at.Name] = append(attrs[at.Name], v.Value)
				if at.FriendlyName != "" && at.FriendlyName != at.Name {
					attrs[at.FriendlyName] = append(attrs[at.FriendlyName], v.Value)
				}
			}
		}
	}
	first := func(configured string, defaults []string) string {
		names := defaults
		if configured != "" {
			names = []string{configured}
		}
		for _, n := range names {
			for _, v := range attrs[n] {
				if v = strings.TrimSpace(v); v != "" {
					return v
				}
			}
		}
		return ""
	}
	x.Subject = nid.Value
	x.Email = first(p.cfg.AttributeMap.Email, defaultEmail)
	if x.Email == "" && nid.Format == string(crewsaml.EmailAddressNameIDFormat) {
		x.Email = nid.Value
	}
	// SAML has no email_verified; the IdP asserting the address is all we
	// get. Linking by email still requires trust_email on the provider.
	x.EmailVerified = x.Email != ""
	x.PreferredUsername = first(p.cfg.AttributeMap.Username, defaultUsername)
	x.DisplayName = first(p.cfg.AttributeMap.DisplayName, defaultDisplay)
	claims := map[string]any{"issuer": a.Issuer.Value, "name_id": nid.Value, "name_id_format": nid.Format}
	ac := map[string]any{}
	for k, v := range attrs {
		ac[k] = v
	}
	claims["attributes"] = ac
	x.Claims = claims
	return x, nil
}

// Check loads the IdP metadata and reports what it found.
func (p *Provider) Check(ctx context.Context) (map[string]any, error) {
	details := map[string]any{"sp_entity_id": p.SPEntityID(), "acs_url": p.base.AcsURL.String()}
	sp, err := p.serviceProvider(ctx)
	if err != nil {
		return details, err
	}
	md := sp.IDPMetadata
	details["idp_entity_id"] = md.EntityID
	details["sso_redirect_url"] = sp.GetSSOBindingLocation(crewsaml.HTTPRedirectBinding)
	details["sso_post_url"] = sp.GetSSOBindingLocation(crewsaml.HTTPPostBinding)
	certs := 0
	for _, d := range md.IDPSSODescriptors {
		for _, kd := range d.KeyDescriptors {
			if kd.Use == "" || kd.Use == "signing" {
				certs += len(kd.KeyInfo.X509Data.X509Certificates)
			}
		}
	}
	details["signing_certificates"] = certs
	if certs == 0 {
		return details, errors.New("idp metadata has no signing certificate")
	}
	if details["sso_redirect_url"] == "" && details["sso_post_url"] == "" {
		return details, errors.New("idp metadata has no HTTP-Redirect or HTTP-POST SSO endpoint")
	}
	return details, nil
}
