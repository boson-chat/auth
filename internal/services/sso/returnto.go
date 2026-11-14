package sso

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/textutil"
)

// Delivery modes at the end of a flow.
const (
	// ModeCookie sets the boson_at/boson_rt cookies and redirects (browser apps
	// on our own origins).
	ModeCookie = "cookie"
	// ModeCode appends ?code= (single use, short-lived) for the client to
	// exchange at POST /v1/sso/exchange (desktop/native apps, other origins).
	ModeCode = "code"
)

const maxReturnTo = 2048

var errReturnTo = apperr.New(400, "invalid_return_to", "return_to is not an allowed URL")

// pattern is one SSO_RETURN_TO_ALLOWED entry:
//
//	https://app.example.com          that origin, any path
//	https://app.example.com/sso/     that origin, paths under /sso/
//	http://127.0.0.1:*               loopback on any port (RFC 8252 native apps)
//	boson://                         a custom scheme, any host/path
type pattern struct {
	scheme, host, port string // port "*" = any; "" = the default port
	path               string // required path prefix ("" = any)
}

func parsePattern(s string) (pattern, error) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(s), "://")
	if !ok || scheme == "" {
		return pattern{}, fmt.Errorf("SSO_RETURN_TO_ALLOWED: %q must look like scheme://host[:port][/path]", s)
	}
	p := pattern{scheme: strings.ToLower(scheme)}
	hostport, path, _ := strings.Cut(rest, "/")
	if path != "" || strings.Contains(rest, "/") {
		p.path = "/" + path
	}
	if h, ok := strings.CutSuffix(hostport, ":*"); ok {
		hostport, p.port = h, "*"
	}
	u, err := url.Parse(p.scheme + "://" + hostport)
	if err != nil || u.User != nil {
		return pattern{}, fmt.Errorf("SSO_RETURN_TO_ALLOWED: %q is not a valid pattern", s)
	}
	p.host = strings.ToLower(u.Hostname())
	if p.port == "" {
		p.port = u.Port()
	}
	if (p.scheme == "http" || p.scheme == "https") && p.host == "" {
		return pattern{}, fmt.Errorf("SSO_RETURN_TO_ALLOWED: %q needs a host", s)
	}
	if p.path == "/" {
		p.path = ""
	}
	return p, nil
}

func (p pattern) match(u *url.URL) bool {
	if strings.ToLower(u.Scheme) != p.scheme {
		return false
	}
	if p.host != "" && strings.ToLower(u.Hostname()) != p.host {
		return false
	}
	if p.port != "*" && u.Port() != p.port {
		return false
	}
	return p.path == "" || strings.HasPrefix(u.EscapedPath(), p.path)
}

// ReturnToPolicy decides where a flow may send the browser back to.
type ReturnToPolicy struct {
	appURL   *url.URL
	patterns []pattern // SSO_RETURN_TO_ALLOWED: code mode only

	mu  sync.RWMutex
	web []pattern // our browser origins (fixed + CORS origins): cookie mode allowed
}

// NewReturnToPolicy: webOrigins (APP_URL, PUBLIC_URL, CORS origins) are
// always allowed and get cookies; allowed are extra patterns (code only).
func NewReturnToPolicy(appURL string, webOrigins, allowed []string) (*ReturnToPolicy, error) {
	au, err := url.Parse(appURL)
	if err != nil || au.Host == "" {
		return nil, fmt.Errorf("APP_URL %q is not an absolute URL", appURL)
	}
	p := &ReturnToPolicy{appURL: au}
	p.web = originPatterns(webOrigins)
	for _, s := range allowed {
		pt, err := parsePattern(s)
		if err != nil {
			return nil, err
		}
		p.patterns = append(p.patterns, pt)
	}
	return p, nil
}

func originPatterns(origins []string) []pattern {
	var out []pattern
	for _, o := range origins {
		if o == "" {
			continue
		}
		u, err := url.Parse(o)
		if err != nil || u.Host == "" {
			continue
		}
		out = append(out, pattern{scheme: strings.ToLower(u.Scheme), host: strings.ToLower(u.Hostname()), port: u.Port()})
	}
	return out
}

// SetWebOrigins replaces the whole list of web origins (cookie mode) with
// origins (e.g. APP_URL, PUBLIC_URL and the reloaded CORS origins).
func (p *ReturnToPolicy) SetWebOrigins(origins []string) {
	web := originPatterns(origins)
	p.mu.Lock()
	p.web = web
	p.mu.Unlock()
}

// Resolve validates return_to and the requested mode ("" = automatic:
// cookie for our web origins, code otherwise) and returns the absolute URL
// and the effective mode.
func (p *ReturnToPolicy) Resolve(returnTo, mode string) (string, string, error) {
	if mode != "" && mode != ModeCookie && mode != ModeCode {
		return "", "", apperr.Invalid("mode must be cookie or code")
	}
	if returnTo == "" {
		returnTo = "/"
	}
	if len(returnTo) > maxReturnTo || !textutil.Storable(returnTo) || strings.ContainsAny(returnTo, "\\\r\n\t") {
		return "", "", errReturnTo
	}
	var u *url.URL
	if strings.HasPrefix(returnTo, "/") {
		if strings.HasPrefix(returnTo, "//") {
			return "", "", errReturnTo
		}
		rel, err := url.Parse(returnTo)
		if err != nil {
			return "", "", errReturnTo
		}
		u = p.appURL.ResolveReference(rel)
	} else {
		var err error
		if u, err = url.Parse(returnTo); err != nil || u.Scheme == "" {
			return "", "", errReturnTo
		}
	}
	if u.User != nil || u.Opaque != "" {
		return "", "", errReturnTo
	}
	web := false
	p.mu.RLock()
	origins := p.web
	p.mu.RUnlock()
	for _, w := range origins {
		if w.match(u) {
			web = true
			break
		}
	}
	allowed := web
	for _, pt := range p.patterns {
		if allowed {
			break
		}
		allowed = pt.match(u)
	}
	if !allowed {
		return "", "", errReturnTo
	}
	switch {
	case mode == "" && web:
		mode = ModeCookie
	case mode == "":
		mode = ModeCode
	case mode == ModeCookie && !web:
		return "", "", apperr.Invalid("cookie mode is only available for this site's own web origins")
	}
	return u.String(), mode, nil
}

// WithParams adds query parameters to a validated return_to URL.
func WithParams(returnTo string, kv ...string) string {
	u, err := url.Parse(returnTo)
	if err != nil {
		return returnTo
	}
	q := u.Query()
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	u.RawQuery = q.Encode()
	return u.String()
}
