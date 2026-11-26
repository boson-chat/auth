package federation

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/boson-chat/auth/config"
)

// Cache lifetimes (the spec allows up to 1 h for discovery and directory).
const (
	discoveryTTL      = 15 * time.Minute
	discoveryFailTTL  = time.Minute
	jwksTTL           = time.Hour
	jwksRefetchMinGap = 10 * time.Second
	directoryTTL      = 15 * time.Minute
	directoryFailTTL  = 2 * time.Minute
	maxDocBytes       = 1 << 20
	maxCacheEntries   = 10000
)

// Discovery is the federation section of a home's boson.json.
type Discovery struct {
	Domain            string
	Version           int
	Issuer            string
	JWKSURI           string
	AssertionEndpoint string
	LoginEndpoint     string
	Accepts           string
	// IRCHost is boson.json's irc.host ("" when absent).
	IRCHost string
}

type cached[T any] struct {
	v       T
	err     error
	expires time.Time
}

type jwksEntry struct {
	keys      map[string]ed25519.PublicKey
	fetchedAt time.Time
	tried     time.Time
}

// remote fetches and caches other servers' discovery documents and JWKS,
// and directory listings.
type remote struct {
	client    *http.Client
	allowHTTP bool
	now       func() time.Time

	mu   sync.Mutex
	disc map[string]cached[*Discovery]
	jwks map[string]*jwksEntry
	dir  map[string]cached[bool]
}

func newRemote(client *http.Client, allowHTTP bool, now func() time.Time) *remote {
	return &remote{client: client, allowHTTP: allowHTTP, now: now,
		disc: map[string]cached[*Discovery]{}, jwks: map[string]*jwksEntry{}, dir: map[string]cached[bool]{}}
}

// NewHTTPClient is the client for discovery, JWKS and directory requests:
// a timeout, no redirects to plain http, and (unless allowPrivate) no
// connections to loopback, private or link-local addresses, so a hostile
// boson.json can't point auth at internal services.
func NewHTTPClient(timeout time.Duration, allowPrivate bool) *http.Client {
	d := &net.Dialer{Timeout: timeout}
	if !allowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if !publicAddr(ip.Unmap()) {
				return fmt.Errorf("federation: refusing to connect to non-public address %s", ip)
			}
			return nil
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = d.DialContext
	tr.Proxy = nil
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" && !allowPrivate {
				return errors.New("redirect to a non-https URL")
			}
			return nil
		},
	}
}

func publicAddr(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() && !ip.IsMulticast() && !ip.IsUnspecified() && !ip.IsInterfaceLocalMulticast() &&
		!netip.MustParsePrefix("100.64.0.0/10").Contains(ip) && !netip.MustParsePrefix("fc00::/7").Contains(ip)
}

func (r *remote) checkURL(s string) error {
	return config.ValidateServiceURL(s, r.allowHTTP)
}

// getJSON fetches u into v. found=false for a 404.
func (r *remote) getJSON(ctx context.Context, u string, v any) (found bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "boson-auth-federation/1")
	resp, err := r.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDocBytes))
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDocBytes)).Decode(v); err != nil {
		return false, fmt.Errorf("GET %s: %w", u, err)
	}
	return true, nil
}

func prune[T any](m map[string]cached[T], now time.Time) {
	if len(m) < maxCacheEntries {
		return
	}
	for k, e := range m {
		if now.After(e.expires) {
			delete(m, k)
		}
	}
	if len(m) >= maxCacheEntries { // still full of live entries: start over
		clear(m)
	}
}

// discovery returns https://<domain>/.well-known/boson.json's federation
// section, cached.
func (r *remote) discovery(ctx context.Context, domain string) (*Discovery, error) {
	now := r.now()
	r.mu.Lock()
	if e, ok := r.disc[domain]; ok && now.Before(e.expires) {
		r.mu.Unlock()
		return e.v, e.err
	}
	r.mu.Unlock()
	d, err := r.fetchDiscovery(ctx, domain)
	ttl := discoveryTTL
	if err != nil {
		ttl = discoveryFailTTL
	}
	r.mu.Lock()
	prune(r.disc, now)
	r.disc[domain] = cached[*Discovery]{v: d, err: err, expires: now.Add(ttl)}
	r.mu.Unlock()
	return d, err
}

func (r *remote) fetchDiscovery(ctx context.Context, domain string) (*Discovery, error) {
	var doc struct {
		IRC *struct {
			Host string `json:"host"`
		} `json:"irc"`
		Federation *struct {
			Version           int    `json:"version"`
			Issuer            string `json:"issuer"`
			JWKSURI           string `json:"jwks_uri"`
			AssertionEndpoint string `json:"assertion_endpoint"`
			LoginEndpoint     string `json:"login_endpoint"`
			Accepts           string `json:"accepts"`
		} `json:"federation"`
	}
	u := "https://" + domain + "/.well-known/boson.json"
	found, err := r.getJSON(ctx, u, &doc)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%s: not found", u)
	}
	f := doc.Federation
	if f == nil {
		return nil, fmt.Errorf("%s has no federation section", u)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported federation version %d", u, f.Version)
	}
	if err := r.checkURL(f.Issuer); err != nil {
		return nil, fmt.Errorf("%s: issuer: %w", u, err)
	}
	if err := r.checkURL(f.JWKSURI); err != nil {
		return nil, fmt.Errorf("%s: jwks_uri: %w", u, err)
	}
	d := &Discovery{Domain: domain, Version: f.Version, Issuer: f.Issuer, JWKSURI: f.JWKSURI,
		AssertionEndpoint: f.AssertionEndpoint, LoginEndpoint: f.LoginEndpoint, Accepts: f.Accepts}
	if doc.IRC != nil {
		d.IRCHost = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(doc.IRC.Host), "."))
	}
	return d, nil
}

// errUnknownKey: the JWKS (even freshly fetched) has no such kid.
var errUnknownKey = errors.New("federation: unknown signing key")

// key returns the Ed25519 key kid of the JWKS at uri, refetching the set
// when it is old or doesn't have kid (at most every jwksRefetchMinGap).
func (r *remote) key(ctx context.Context, uri, kid string) (ed25519.PublicKey, error) {
	now := r.now()
	r.mu.Lock()
	e := r.jwks[uri]
	if e != nil {
		if k, ok := e.keys[kid]; ok && now.Sub(e.fetchedAt) < jwksTTL {
			r.mu.Unlock()
			return k, nil
		}
		if now.Sub(e.tried) < jwksRefetchMinGap {
			k, ok := e.keys[kid]
			r.mu.Unlock()
			if ok {
				return k, nil
			}
			return nil, errUnknownKey
		}
	}
	r.mu.Unlock()

	keys, err := r.fetchJWKS(ctx, uri)
	r.mu.Lock()
	defer r.mu.Unlock()
	if e = r.jwks[uri]; e == nil {
		if len(r.jwks) >= maxCacheEntries {
			clear(r.jwks)
		}
		e = &jwksEntry{}
		r.jwks[uri] = e
	}
	e.tried = now
	if err != nil {
		// Keep serving the keys we had (a home briefly down mustn't break
		// sign-ins with keys we already know).
		if k, ok := e.keys[kid]; ok {
			return k, nil
		}
		return nil, err
	}
	e.keys, e.fetchedAt = keys, now
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, errUnknownKey
}

func (r *remote) fetchJWKS(ctx context.Context, uri string) (map[string]ed25519.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty, Crv, X, Kid, Use string
		} `json:"keys"`
	}
	found, err := r.getJSON(ctx, uri, &set)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%s: not found", uri)
	}
	out := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		if k.Kid == "" || k.Kty != "OKP" || k.Crv != "Ed25519" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			continue
		}
		out[k.Kid] = ed25519.PublicKey(x)
	}
	return out, nil
}

// listed reports whether any of hostnames has a verified listing in the
// directory at dirURL (GET /v1/networks/lookup?hostname=, which only shows
// verified listings to anonymous callers).
func (r *remote) listed(ctx context.Context, dirURL string, hostnames []string) (bool, error) {
	var firstErr error
	for _, h := range hostnames {
		ok, err := r.listedOne(ctx, dirURL, h)
		if ok {
			return true, nil
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return false, firstErr
}

func (r *remote) listedOne(ctx context.Context, dirURL, hostname string) (bool, error) {
	key := dirURL + "|" + hostname
	now := r.now()
	r.mu.Lock()
	prev, had := r.dir[key]
	if had && now.Before(prev.expires) {
		r.mu.Unlock()
		return prev.v, prev.err
	}
	r.mu.Unlock()
	var listing struct {
		Network *struct {
			Hostname string `json:"hostname"`
			Status   string `json:"status"`
		} `json:"network"`
	}
	found, err := r.getJSON(ctx, dirURL+"/v1/networks/lookup?hostname="+url.QueryEscape(hostname), &listing)
	ok := err == nil && found && listing.Network != nil && listing.Network.Status == "verified" &&
		strings.EqualFold(strings.TrimSuffix(listing.Network.Hostname, "."), hostname)
	ttl := directoryTTL
	if err != nil && had && prev.v {
		// The directory is unreachable: keep a verified listing we saw
		// (stale-if-error) rather than lock its users out.
		ok, err = true, nil
	}
	if err != nil || !ok {
		ttl = directoryFailTTL
	}
	r.mu.Lock()
	prune(r.dir, now)
	r.dir[key] = cached[bool]{v: ok, err: err, expires: now.Add(ttl)}
	r.mu.Unlock()
	return ok, err
}
