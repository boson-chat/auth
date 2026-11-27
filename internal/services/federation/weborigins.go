package federation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/logger"
)

// Web origins (GET /v1/web-origins): the browser origins of the Boson web
// clients this install's voice, video and files services accept. That is
// this install's own web client (WEB_CLIENT_URL) plus, for every verified
// listing in the directory (directory_url; it carries the listings of the
// directories it follows too), the web client its boson.json names
// ("web": {"url": "https://chat.example.org"}). A newly verified server's
// web client is accepted from the next refresh.
const (
	// webOriginsInterval: how often the list is rebuilt.
	webOriginsInterval = 10 * time.Minute
	// webOriginsRetry: the wait after a failed rebuild (the last good
	// list stays meanwhile).
	webOriginsRetry = time.Minute
	// webOriginsFetchTimeout bounds one listing's boson.json fetch.
	webOriginsFetchTimeout = 5 * time.Second
	// webOriginsConcurrency bounds the boson.json fetches in flight.
	webOriginsConcurrency = 8
	// Directory pages of 100 listings, at most this many (10 000 listings).
	webOriginsPageSize = 100
	webOriginsMaxPages = 100
	// MaxWebOrigins bounds the list.
	MaxWebOrigins = 5000
)

// WebOrigins is GET /v1/web-origins.
type WebOrigins struct {
	// Origins: scheme://host[:port], lower-case, no trailing slash; the
	// install's own web client first, then the rest sorted.
	Origins []string `json:"origins"`
	// Own is this install's web client origin ("" without WEB_CLIENT_URL).
	Own string `json:"own"`
	// Directory is the directory the list was built from ("" = none).
	Directory string `json:"directory"`
	// UpdatedAt: when the directory part was last built successfully;
	// null before the first success (only Own is listed then).
	UpdatedAt *time.Time `json:"updated_at"`
}

// NormalizeOrigin returns raw (a URL or an origin) as a browser origin,
// scheme://host[:port] with the scheme and host lower-cased, the default
// port dropped and any path, trailing slash or trailing dot removed. Only
// https unless allowHTTP. ok=false for anything that isn't a web origin
// (user info, query, fragment, no host, IP literals unless allowHTTP).
func NormalizeOrigin(raw string, allowHTTP bool) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && (scheme != "http" || !allowHTTP) {
		return "", false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return "", false
	}
	if allowHTTP {
		if strings.ContainsAny(host, "/@ ") {
			return "", false
		}
	} else if net.ParseIP(host) != nil || !config.ValidDomain(host) {
		return "", false
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		if !(scheme == "https" && n == 443) && !(scheme == "http" && n == 80) {
			host += ":" + strconv.Itoa(n)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return "", false
	}
	return scheme + "://" + host, true
}

// originHost is the host of a normalised origin (no port).
func originHost(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// webOriginsState is the last good list and what built it.
type webOriginsState struct {
	mu        sync.Mutex
	dir       string
	byHost    map[string]string // listing hostname → web origin ("" = none)
	updatedAt time.Time
}

// WebOrigins returns the current list (never an error: without a good
// directory build it is the own origin only).
func (s *FederationService) WebOrigins(ctx context.Context) (WebOrigins, error) {
	own := s.ownWebOrigin()
	w := &s.webOrigins
	w.mu.Lock()
	defer w.mu.Unlock()
	out := WebOrigins{Own: own, Directory: w.dir, Origins: []string{}}
	if own != "" {
		out.Origins = append(out.Origins, own)
	}
	seen := map[string]bool{own: true}
	rest := make([]string, 0, len(w.byHost))
	for _, o := range w.byHost {
		if o != "" && !seen[o] {
			seen[o] = true
			rest = append(rest, o)
		}
	}
	sort.Strings(rest)
	if len(rest) > MaxWebOrigins {
		rest = rest[:MaxWebOrigins]
	}
	out.Origins = append(out.Origins, rest...)
	if !w.updatedAt.IsZero() {
		t := w.updatedAt
		out.UpdatedAt = &t
	}
	return out, nil
}

// ownWebOrigin is the origin of WEB_CLIENT_URL ("" when unset). http is
// allowed here: it is the admin's own setting (local development).
func (s *FederationService) ownWebOrigin() string {
	o, _ := NormalizeOrigin(s.Config.HTTPConfig.WebClientURL, true)
	return o
}

// RunWebOrigins builds the list at start and every webOriginsInterval
// (webOriginsRetry after a failure) until ctx is done.
func (s *FederationService) RunWebOrigins(ctx context.Context) {
	for {
		wait := webOriginsInterval
		if err := s.RefreshWebOrigins(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.FromCtx(ctx).Warn().Err(err).Msg("web origins: keeping the last list")
			wait = webOriginsRetry
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// RefreshWebOrigins rebuilds the list from the directory. On an error the
// last good list stays.
func (s *FederationService) RefreshWebOrigins(ctx context.Context) error {
	st, err := s.Settings(ctx)
	if err != nil {
		return err
	}
	dir := strings.TrimRight(strings.TrimSpace(st.DirectoryURL), "/")
	w := &s.webOrigins
	if dir == "" {
		w.mu.Lock()
		w.dir, w.byHost, w.updatedAt = "", nil, s.now()
		w.mu.Unlock()
		return nil
	}
	if err := s.remote.checkURL(dir); err != nil {
		return fmt.Errorf("directory_url: %w", err)
	}
	hosts, err := s.remote.verifiedHostnames(ctx, dir)
	if err != nil {
		return err
	}
	w.mu.Lock()
	prev := w.byHost
	if w.dir != dir {
		prev = nil // another directory: nothing of the old list carries over
	}
	w.mu.Unlock()

	next := make(map[string]string, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, webOriginsConcurrency)
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			fctx, cancel := context.WithTimeout(ctx, webOriginsFetchTimeout)
			defer cancel()
			o, err := s.remote.webOriginOf(fctx, h)
			if err != nil {
				// Couldn't tell (down, timeout, bad answer): keep what
				// this listing had (stale-if-error).
				o = prev[h]
			}
			mu.Lock()
			next[h] = o
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	w.mu.Lock()
	w.dir, w.byHost, w.updatedAt = dir, next, s.now()
	w.mu.Unlock()
	return nil
}

// verifiedHostnames lists the hostnames of every verified listing in the
// directory at dirURL (GET /v1/networks, which only lists verified
// listings to anonymous callers; the status is checked anyway), NSFW ones
// included, sorted by name, every page.
func (r *remote) verifiedHostnames(ctx context.Context, dirURL string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < webOriginsMaxPages; page++ {
		q := url.Values{"nsfw": {"true"}, "sort": {"name"}, "limit": {strconv.Itoa(webOriginsPageSize)}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var body struct {
			Networks []struct {
				Hostname string `json:"hostname"`
				Status   string `json:"status"`
			} `json:"networks"`
			NextCursor *string `json:"next_cursor"`
		}
		found, err := r.getJSON(ctx, dirURL+"/v1/networks?"+q.Encode(), &body)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("%s/v1/networks: not found", dirURL)
		}
		for _, n := range body.Networks {
			h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n.Hostname)), ".")
			if n.Status != "verified" || !config.ValidDomain(h) || seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
		if body.NextCursor == nil || *body.NextCursor == "" || len(body.Networks) == 0 {
			return out, nil
		}
		cursor = *body.NextCursor
	}
	logger.FromCtx(ctx).Warn().Int("listings", len(out)).Msg("web origins: directory has more pages than read")
	return out, nil
}

// errNoBosonJSON: a domain has no (usable) boson.json.
var errNoBosonJSON = errors.New("no boson.json")

// webOriginOf is the web client origin of the Boson server a listing
// (an IRC hostname) belongs to: boson.json at the hostname minus its
// first label (as the app finds a server: irc.example.org →
// example.org), else at the hostname itself. "" with a nil error when
// there is none: no boson.json, no web section, or one that isn't https
// on that domain or a subdomain. An error only when the first place
// couldn't be read (unreachable, timeout, 5xx) and the second had nothing.
func (r *remote) webOriginOf(ctx context.Context, hostname string) (string, error) {
	var candidates []string
	if _, rest, ok := strings.Cut(hostname, "."); ok && strings.Contains(rest, ".") {
		candidates = append(candidates, rest)
	}
	candidates = append(candidates, hostname)
	var primaryErr error
	for i, domain := range candidates {
		o, err := r.webOriginAt(ctx, domain, hostname)
		if err == nil {
			return o, nil
		}
		if i == 0 && !errors.Is(err, errNoBosonJSON) {
			primaryErr = err
		}
	}
	return "", primaryErr
}

// webOriginAt reads https://<domain>/.well-known/boson.json for the
// listing hostname: errNoBosonJSON when it is missing, unusable or
// belongs to another IRC network (irc.host set and not hostname); other
// errors when it couldn't be read.
func (r *remote) webOriginAt(ctx context.Context, domain, hostname string) (string, error) {
	var doc struct {
		IRC *struct {
			Host string `json:"host"`
		} `json:"irc"`
		Web *struct {
			URL string `json:"url"`
		} `json:"web"`
	}
	found, err := r.getJSON(ctx, "https://"+domain+"/.well-known/boson.json", &doc)
	if err != nil {
		var se *statusError
		var nerr net.Error
		switch {
		case ctx.Err() != nil, errors.As(err, &nerr), errors.As(err, &se) && se.code >= 500:
			return "", err
		}
		// A 4xx or a body that isn't the JSON object: nothing usable.
		return "", fmt.Errorf("%w: %v", errNoBosonJSON, err)
	}
	if !found {
		return "", errNoBosonJSON
	}
	if doc.IRC != nil {
		if h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(doc.IRC.Host)), "."); h != "" && h != hostname {
			return "", errNoBosonJSON
		}
	}
	if doc.Web == nil || doc.Web.URL == "" {
		return "", nil
	}
	o, ok := NormalizeOrigin(doc.Web.URL, false)
	if !ok {
		return "", nil
	}
	// Only the domain's own web client: it or a subdomain of it.
	if h := originHost(o); h != domain && !strings.HasSuffix(h, "."+domain) {
		return "", nil
	}
	return o, nil
}
