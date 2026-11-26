package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/boson-chat/auth/internal/configfile"
)

// Federation trust modes (FEDERATION_MODE): which home servers' users may
// sign in here with a federated identity (docs/federation.md).
const (
	// FederationOff: neither issue assertions nor accept them.
	FederationOff = "off"
	// FederationAllowlist: only home domains in FEDERATION_ALLOW.
	FederationAllowlist = "allowlist"
	// FederationDirectory: home domains with a verified listing in the
	// directory (FEDERATION_DIRECTORY_URL).
	FederationDirectory = "directory"
	// FederationOpen: any home domain with valid discovery.
	FederationOpen = "open"
)

// ValidFederationMode reports whether v is a FEDERATION_MODE value.
func ValidFederationMode(v string) bool {
	switch v {
	case FederationOff, FederationAllowlist, FederationDirectory, FederationOpen:
		return true
	}
	return false
}

// DefaultDirectoryURL is the main Boson directory.
const DefaultDirectoryURL = "https://directory.boson.chat"

// FederationConfig is Boson federated login (docs/federation.md). Mode,
// Allow, Block, DirectoryURL, RemoteUploadQuota, RemoteMaxFile and
// RemoteVoice are defaults: admins change them at runtime
// (PATCH /v1/admin/federation/settings).
type FederationConfig struct {
	// off | allowlist | directory | open. Also this server's `accepts` in
	// its federation metadata; off stops issuing assertions too.
	Mode string `default:"directory" env:"FEDERATION_MODE"`
	// Home domains accepted in allowlist mode (comma-separated). An entry
	// "*.example.org" matches example.org and every subdomain.
	Allow string `env:"FEDERATION_ALLOW"`
	// Home domains refused in every mode (same syntax).
	Block string `env:"FEDERATION_BLOCK"`
	// The directory whose verified listings directory mode trusts.
	DirectoryURL string `default:"https://directory.boson.chat" env:"FEDERATION_DIRECTORY_URL"`
	// This install's own domain: boson_domain in the assertions it issues
	// (the domain whose /.well-known/boson.json lists this issuer). Default:
	// the issuer's host without a leading "auth." label.
	Domain string `env:"FEDERATION_DOMAIN"`
	// Role given to every federated account when it is created (matched by
	// name/slug, created when missing). Empty: no role (Member only).
	RemoteRole string `default:"Remote" env:"FEDERATION_REMOTE_ROLE"`
	// Upload quota per rolling window and largest file for federated users,
	// pushed to the files service as a per-user override (FILES_INTERNAL_URL).
	// Sizes like 500MB or 2GiB; empty = the files service's account default.
	RemoteUploadQuota string `env:"FEDERATION_REMOTE_UPLOAD_QUOTA"`
	RemoteMaxFile     string `env:"FEDERATION_REMOTE_MAX_FILE"`
	// Federated users may get voice (and video) tokens.
	RemoteVoice bool `default:"true" env:"FEDERATION_REMOTE_VOICE"`
	// Timeout for discovery, JWKS and directory requests.
	HTTPTimeout time.Duration `default:"10s" env:"FEDERATION_HTTP_TIMEOUT"`
	// Accept http:// discovery, JWKS and directory URLs (dev only).
	AllowHTTP bool `default:"false" env:"FEDERATION_ALLOW_HTTP"`
	// Assertions issued per user: burst and per minute.
	AssertBurst     int     `default:"10" env:"FEDERATION_ASSERT_BURST"`
	AssertPerMinute float64 `default:"10" env:"FEDERATION_ASSERT_PER_MINUTE"`
}

// Timeout is FEDERATION_HTTP_TIMEOUT (10 s when unset).
func (f FederationConfig) Timeout() time.Duration {
	if f.HTTPTimeout <= 0 {
		return 10 * time.Second
	}
	return f.HTTPTimeout
}

// AssertLimit is the per-user assertion rate limit (burst, per minute).
func (f FederationConfig) AssertLimit() (int, float64) {
	b, r := f.AssertBurst, f.AssertPerMinute
	if b <= 0 {
		b = 10
	}
	if r <= 0 {
		r = 10
	}
	return b, r
}

// FilesInternalConfig is the files service's internal API, used to set the
// upload quota of federated users (PUT /internal/quota/{user}).
type FilesInternalConfig struct {
	// e.g. http://files:3001. Empty: no per-user overrides are pushed.
	URL   string `env:"FILES_INTERNAL_URL"`
	Token string `env:"FILES_INTERNAL_TOKEN"`
}

// FederationDomain is FEDERATION_DOMAIN, or the issuer's host without a
// leading "auth.".
func (c Config) FederationDomain() string {
	if d := strings.ToLower(strings.TrimSpace(c.FederationConfig.Domain)); d != "" {
		return d
	}
	u, err := url.Parse(c.TokenConfig.Issuer)
	if err != nil {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if rest, ok := strings.CutPrefix(h, "auth."); ok && strings.Contains(rest, ".") {
		h = rest
	}
	if !ValidDomain(h) {
		return "" // e.g. localhost: set FEDERATION_DOMAIN to issue assertions
	}
	return h
}

// ValidateFederation checks the federation settings.
func (c Config) ValidateFederation() error {
	f := c.FederationConfig
	if f.Mode != "" && !ValidFederationMode(f.Mode) { // "" = directory (struct literals)
		return fmt.Errorf("FEDERATION_MODE must be off, allowlist, directory or open, got %q", f.Mode)
	}
	for name, v := range map[string]string{"FEDERATION_ALLOW": f.Allow, "FEDERATION_BLOCK": f.Block} {
		if _, err := ParseDomainList(SplitList(v)); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if err := ValidateServiceURL(f.DirectoryURL, f.AllowHTTP); f.DirectoryURL != "" && err != nil {
		return fmt.Errorf("FEDERATION_DIRECTORY_URL: %w", err)
	}
	if d := strings.ToLower(strings.TrimSpace(f.Domain)); d != "" && !ValidDomain(d) {
		return fmt.Errorf("FEDERATION_DOMAIN must be a domain such as example.org, got %q", d)
	}
	for name, v := range map[string]string{"FEDERATION_REMOTE_UPLOAD_QUOTA": f.RemoteUploadQuota, "FEDERATION_REMOTE_MAX_FILE": f.RemoteMaxFile} {
		if strings.TrimSpace(v) == "" {
			continue
		}
		if n, err := ParseSize(v); err != nil || n <= 0 {
			return fmt.Errorf("%s must be a positive size such as 500MB, got %q", name, v)
		}
	}
	// Zero values (struct literals) mean the defaults; negatives are errors.
	if f.HTTPTimeout < 0 {
		return errors.New("FEDERATION_HTTP_TIMEOUT must be positive")
	}
	if f.AssertBurst < 0 || f.AssertPerMinute < 0 {
		return errors.New("FEDERATION_ASSERT_BURST and FEDERATION_ASSERT_PER_MINUTE must be positive")
	}
	if u := strings.TrimSpace(c.FilesInternalConfig.URL); u != "" {
		if p, err := url.Parse(u); err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
			return fmt.Errorf("FILES_INTERNAL_URL must be an http(s) URL such as http://files:3001, got %q", u)
		}
	}
	return nil
}

// ValidateServiceURL checks an https URL (http too when allowHTTP).
func ValidateServiceURL(s string, allowHTTP bool) error {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("%q is not a URL such as https://directory.example.org", s)
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !allowHTTP) {
		return fmt.Errorf("%q must be https", s)
	}
	return nil
}

// ValidDomain reports whether s is a lower-case DNS name with at least one
// dot (no port, no trailing dot), labels of 1-63 letters, digits or '-'.
func ValidDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ParseDomainList normalises allow / block entries: lower-case domains or
// "*.domain". Duplicates are dropped, order kept.
func ParseDomainList(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		e := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if e == "" {
			continue
		}
		if !ValidDomain(strings.TrimPrefix(e, "*.")) {
			return nil, fmt.Errorf("%q is not a domain (example.org or *.example.org)", raw)
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out, nil
}

// DomainListMatches reports whether domain is in the list: an entry
// "example.org" matches only that domain, "*.example.org" it and every
// subdomain.
func DomainListMatches(list []string, domain string) bool {
	domain = strings.ToLower(domain)
	for _, e := range list {
		if base, ok := strings.CutPrefix(e, "*."); ok {
			if domain == base || strings.HasSuffix(domain, "."+base) {
				return true
			}
		} else if domain == e {
			return true
		}
	}
	return false
}

// ParseSize parses a byte count or a number with a unit: KB/MB/GB/TB are
// powers of 1000, KiB/MiB/GiB/TiB powers of 1024 (as the files service).
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	num, unit := s[:i], strings.ToUpper(strings.TrimSpace(s[i:]))
	if num == "" {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	mult := map[string]float64{"": 1, "B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12,
		"KIB": 1 << 10, "MIB": 1 << 20, "GIB": 1 << 30, "TIB": 1 << 40}[unit]
	if mult == 0 {
		return 0, fmt.Errorf("invalid size unit in %q", s)
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int64(f * mult), nil
}

// Stack config file keys of auth.federation (file > env > default).
const (
	KeyFederationMode              = "auth.federation.mode"
	KeyFederationAllow             = "auth.federation.allow"
	KeyFederationBlock             = "auth.federation.block"
	KeyFederationDirectoryURL      = "auth.federation.directory_url"
	KeyFederationRemoteUploadQuota = "auth.federation.remote_upload_quota"
	KeyFederationRemoteVoice       = "auth.federation.remote_voice"
)

// MaxFederationDomains bounds the allow and block lists.
const MaxFederationDomains = 1000

// FederationFile is the auth.federation section; nil / unset = not in the file.
type FederationFile struct {
	Mode              *string
	Allow             []string
	AllowSet          bool
	Block             []string
	BlockSet          bool
	DirectoryURL      *string
	RemoteUploadQuota *string
	RemoteVoice       *bool
}

// Fields lists the settings set in the file by their JSON names (mode,
// allow, block, directory_url, remote_upload_quota, remote_voice).
func (f FederationFile) Fields() []string {
	var out []string
	add := func(name string, set bool) {
		if set {
			out = append(out, name)
		}
	}
	add("mode", f.Mode != nil)
	add("allow", f.AllowSet)
	add("block", f.BlockSet)
	add("directory_url", f.DirectoryURL != nil)
	add("remote_upload_quota", f.RemoteUploadQuota != nil)
	add("remote_voice", f.RemoteVoice != nil)
	return out
}

func loadFederation(auth *configfile.Section, f *FileConfig) error {
	sec, err := auth.Sub("federation")
	if err != nil {
		return err
	}
	ff := &f.Federation
	if v, err := sec.String("mode"); err != nil {
		return err
	} else if v != nil {
		m := strings.TrimSpace(*v)
		if !ValidFederationMode(m) {
			return sec.Errorf("mode", "must be off, allowlist, directory or open, got %q", *v)
		}
		ff.Mode = &m
	}
	list := func(key string, dst *[]string, set *bool) error {
		l, ok, err := sec.Strings(key)
		if err != nil || !ok {
			return err
		}
		if len(l) > MaxFederationDomains {
			return sec.Errorf(key, "may have at most %d entries", MaxFederationDomains)
		}
		for i, d := range l {
			if _, err := ParseDomainList([]string{d}); err != nil {
				return configfile.At(sec.ItemNode(key, i), "auth.federation.%s: %v", key, err)
			}
		}
		out, _ := ParseDomainList(l)
		*dst, *set = out, true
		return nil
	}
	if err := list("allow", &ff.Allow, &ff.AllowSet); err != nil {
		return err
	}
	if err := list("block", &ff.Block, &ff.BlockSet); err != nil {
		return err
	}
	if v, err := sec.String("directory_url"); err != nil {
		return err
	} else if v != nil {
		u := strings.TrimRight(strings.TrimSpace(*v), "/")
		if err := ValidateServiceURL(u, false); err != nil {
			return sec.Errorf("directory_url", "must be an https URL such as https://directory.boson.chat, got %q", *v)
		}
		ff.DirectoryURL = &u
	}
	if v, err := sec.String("remote_upload_quota"); err != nil {
		return err
	} else if v != nil {
		q := strings.TrimSpace(*v)
		if q != "" {
			if n, err := ParseSize(q); err != nil || n <= 0 {
				return sec.Errorf("remote_upload_quota", "must be a size such as 1GB (empty = the account quota), got %q", *v)
			}
		}
		ff.RemoteUploadQuota = &q
	}
	if v, err := sec.Bool("remote_voice"); err != nil {
		return err
	} else {
		ff.RemoteVoice = v
	}
	f.Unknown = append(f.Unknown, sec.Unknown("mode", "allow", "block", "directory_url", "remote_upload_quota", "remote_voice")...)
	return nil
}

func (c *Config) withFederation(ff FederationFile) {
	fc := &c.FederationConfig
	if ff.Mode != nil {
		fc.Mode = *ff.Mode
	}
	if ff.AllowSet {
		fc.Allow = strings.Join(ff.Allow, ",")
	}
	if ff.BlockSet {
		fc.Block = strings.Join(ff.Block, ",")
	}
	if ff.DirectoryURL != nil {
		fc.DirectoryURL = *ff.DirectoryURL
	}
	if ff.RemoteUploadQuota != nil {
		fc.RemoteUploadQuota = *ff.RemoteUploadQuota
	}
	if ff.RemoteVoice != nil {
		fc.RemoteVoice = *ff.RemoteVoice
	}
}

func (f FederationFile) flatten(m map[string]any) {
	put := func(key string, set bool, v any) {
		if set {
			m[key] = v
		}
	}
	put(KeyFederationMode, f.Mode != nil, deref(f.Mode))
	put(KeyFederationAllow, f.AllowSet, f.Allow)
	put(KeyFederationBlock, f.BlockSet, f.Block)
	put(KeyFederationDirectoryURL, f.DirectoryURL != nil, deref(f.DirectoryURL))
	put(KeyFederationRemoteUploadQuota, f.RemoteUploadQuota != nil, deref(f.RemoteUploadQuota))
	put(KeyFederationRemoteVoice, f.RemoteVoice != nil, deref(f.RemoteVoice))
}
