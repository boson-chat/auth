// Package config holds the service configuration, loaded from env vars.
//
// Durations use Go syntax (15m, 720h); days are not accepted, so 30 days is 720h.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/jinzhu/configor"
)

type Config struct {
	AppConfig       AppConfig
	HTTPConfig      HTTPConfig
	DBConfig        DBConfig
	TokenConfig     TokenConfig
	AccountConfig   AccountConfig
	PasswordConfig  PasswordConfig
	SMTPConfig      SMTPConfig
	InternalConfig  InternalConfig
	RateLimitConfig RateLimitConfig
	TelemetryConfig TelemetryConfig
}

type AppConfig struct {
	APPName  string `default:"auth"`
	Env      string `default:"development" env:"ENV"`
	Version  string `default:"dev" env:"VERSION"`
	LogLevel string `default:"info" env:"LOG_LEVEL"`
	// Product name used in emails.
	SiteName string `default:"boson" env:"SITE_NAME"`
}

type HTTPConfig struct {
	// Public API listener (behind Caddy).
	Addr string `default:":8080" env:"HTTP_ADDR"`
	// Internal listener (/metrics, /internal/v1/*). Never expose publicly.
	InternalAddr string `default:":8081" env:"INTERNAL_ADDR"`
	// Externally visible base URL of this service, e.g. https://auth.example.com.
	PublicURL string `default:"http://localhost:8080" env:"PUBLIC_URL"`
	// Base URL for links in emails (verify / reset pages). Defaults to PUBLIC_URL,
	// whose built-in /verify-email and /reset-password pages work without a web app.
	AppURL string `env:"APP_URL"`
	// Comma-separated CIDRs (or IPs) whose X-Forwarded-For is trusted.
	TrustedProxies string `env:"TRUSTED_PROXIES"`
	// Comma-separated origins allowed to call the API with credentials (CORS).
	// Defaults to the origin of APP_URL.
	CORSAllowedOrigins string `env:"CORS_ALLOWED_ORIGINS"`
	// Secure flag on cookies. Only turn off for plain-http local dev.
	CookieSecure bool `default:"true" env:"COOKIE_SECURE"`
	// Cookie Domain attribute; empty = host-only cookie.
	CookieDomain string `env:"COOKIE_DOMAIN"`
}

type DBConfig struct {
	// Full connection URL; when set it wins over the DB_* parts.
	URL      string `env:"DATABASE_URL"`
	Host     string `default:"localhost" env:"DB_HOST"`
	Port     uint   `default:"5432" env:"DB_PORT"`
	User     string `default:"auth" env:"DB_USER"`
	Password string `env:"DB_PASSWORD"`
	Name     string `default:"auth" env:"DB_NAME"`
	SSLMode  string `default:"disable" env:"DB_SSLMODE"`
	// Run migrations up on `serve` start.
	AutoMigrate bool `default:"true" env:"AUTO_MIGRATE"`
	MaxConns    int  `default:"20" env:"DB_MAX_CONNS"`
}

// DSN returns the connection URL.
func (c DBConfig) DSN() string {
	if c.URL != "" {
		return c.URL
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.User, c.Password),
		Host:     fmt.Sprintf("%s:%d", c.Host, c.Port),
		Path:     "/" + c.Name,
		RawQuery: url.Values{"sslmode": {c.SSLMode}}.Encode(),
	}
	return u.String()
}

type TokenConfig struct {
	// iss claim. Defaults to PUBLIC_URL.
	Issuer         string        `env:"ISSUER"`
	AccessTokenTTL time.Duration `default:"15m" env:"ACCESS_TOKEN_TTL"`
	// Idle lifetime of a refresh token; every refresh issues a new one.
	RefreshTokenTTL time.Duration `default:"720h" env:"REFRESH_TOKEN_TTL"`
	// Absolute session lifetime; refresh never extends past it.
	SessionMaxAge time.Duration `default:"2160h" env:"SESSION_MAX_AGE"`
	VoiceTokenTTL time.Duration `default:"5m" env:"VOICE_TOKEN_TTL"`
	// How often the signing key is replaced.
	KeyRotation time.Duration `default:"720h" env:"KEY_ROTATION"`
	// How long a new key is published in JWKS before it signs anything, so
	// verifiers with a cached JWKS already know it. Keep above the JWKS cache time.
	KeyPublishLead time.Duration `default:"15m" env:"KEY_PUBLISH_LEAD"`
	// 32 random bytes, base64. Encrypts signing keys at rest (AES-256-GCM).
	KeyEncryptionKey string `env:"AUTH_KEY_ENCRYPTION_KEY"`
}

// MaxTokenTTL is the longest lifetime of any JWT this service signs.
func (c TokenConfig) MaxTokenTTL() time.Duration {
	return max(c.AccessTokenTTL, c.VoiceTokenTTL)
}

// DecodeKeyEncryptionKey parses AUTH_KEY_ENCRYPTION_KEY.
func (c TokenConfig) DecodeKeyEncryptionKey() ([]byte, error) {
	s := strings.TrimSpace(c.KeyEncryptionKey)
	if s == "" {
		return nil, errors.New("AUTH_KEY_ENCRYPTION_KEY is not set (32 random bytes, base64; generate with `auth keys gen-kek`)")
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) != 32 {
				return nil, fmt.Errorf("AUTH_KEY_ENCRYPTION_KEY must decode to 32 bytes, got %d", len(b))
			}
			return b, nil
		}
	}
	return nil, errors.New("AUTH_KEY_ENCRYPTION_KEY is not valid base64")
}

const (
	RegistrationOpen   = "open"
	RegistrationInvite = "invite"
	RegistrationClosed = "closed"
)

type AccountConfig struct {
	// open | invite | closed
	Registration             string        `default:"open" env:"REGISTRATION"`
	RequireEmailVerification bool          `default:"true" env:"REQUIRE_EMAIL_VERIFICATION"`
	EmailVerifyTTL           time.Duration `default:"24h" env:"EMAIL_VERIFY_TTL"`
	PasswordResetTTL         time.Duration `default:"30m" env:"PASSWORD_RESET_TTL"`
}

// PasswordConfig holds the argon2id parameters used for new hashes. Existing
// hashes keep the parameters they were made with (PHC string) and are
// upgraded on the next successful login.
type PasswordConfig struct {
	MemoryKiB   uint32 `default:"65536" env:"ARGON2_MEMORY_KIB"`
	Iterations  uint32 `default:"3" env:"ARGON2_ITERATIONS"`
	Parallelism uint8  `default:"2" env:"ARGON2_PARALLELISM"`
}

type SMTPConfig struct {
	// Empty = log-only mailer (dev): links are written to the log instead.
	Host     string `env:"SMTP_HOST"`
	Port     int    `default:"587" env:"SMTP_PORT"`
	User     string `env:"SMTP_USER"`
	Password string `env:"SMTP_PASSWORD"`
	From     string `default:"boson <no-reply@localhost>" env:"SMTP_FROM"`
	// starttls (required STARTTLS) | tls (implicit TLS, port 465) | none (dev only, e.g. mailpit)
	TLS string `default:"starttls" env:"SMTP_TLS"`
}

type InternalConfig struct {
	// Shared secret for /internal/v1/*, sent as X-Internal-Token. Empty disables the internal API.
	APIToken string `env:"INTERNAL_API_TOKEN"`
}

// RateLimitConfig: token buckets per client IP and per account identifier,
// separately for each sensitive endpoint group.
type RateLimitConfig struct {
	Enabled bool `default:"true" env:"RATE_LIMIT_ENABLED"`
	// Per IP: burst and sustained requests per minute.
	IPBurst     int     `default:"20" env:"RATE_LIMIT_IP_BURST"`
	IPPerMinute float64 `default:"10" env:"RATE_LIMIT_IP_PER_MINUTE"`
	// Per account (username/email/token target): burst and sustained per minute.
	AccountBurst     int     `default:"5" env:"RATE_LIMIT_ACCOUNT_BURST"`
	AccountPerMinute float64 `default:"2" env:"RATE_LIMIT_ACCOUNT_PER_MINUTE"`
}

// TelemetryConfig controls metrics export. Prometheus on the internal
// listener's /metrics is always on; OTLP push is on when an endpoint is set.
type TelemetryConfig struct {
	OTLPEndpoint        string `env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	OTLPMetricsEndpoint string `env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"`
	// http/protobuf (default) or grpc.
	OTLPProtocol        string `env:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	OTLPMetricsProtocol string `env:"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"`
	// "none" turns OTLP push off even when an endpoint is set.
	MetricsExporter string `env:"OTEL_METRICS_EXPORTER"`
}

// LoadConfig reads the configuration from the environment and fills derived defaults.
func LoadConfig() (Config, error) {
	var cfg Config
	if err := configor.New(&configor.Config{ENVPrefix: "-", Silent: true}).Load(&cfg); err != nil {
		return cfg, err
	}
	cfg.ApplyDefaults()
	return cfg, cfg.Validate()
}

// ApplyDefaults fills values derived from other settings.
func (c *Config) ApplyDefaults() {
	c.HTTPConfig.PublicURL = strings.TrimRight(c.HTTPConfig.PublicURL, "/")
	if c.HTTPConfig.AppURL == "" {
		c.HTTPConfig.AppURL = c.HTTPConfig.PublicURL
	}
	c.HTTPConfig.AppURL = strings.TrimRight(c.HTTPConfig.AppURL, "/")
	if c.TokenConfig.Issuer == "" {
		c.TokenConfig.Issuer = c.HTTPConfig.PublicURL
	}
	if c.HTTPConfig.CORSAllowedOrigins == "" {
		if u, err := url.Parse(c.HTTPConfig.AppURL); err == nil && u.Host != "" {
			c.HTTPConfig.CORSAllowedOrigins = u.Scheme + "://" + u.Host
		}
	}
}

// Validate checks settings that would otherwise fail confusingly later.
func (c Config) Validate() error {
	switch c.AccountConfig.Registration {
	case RegistrationOpen, RegistrationInvite, RegistrationClosed:
	default:
		return fmt.Errorf("REGISTRATION must be open, invite or closed, got %q", c.AccountConfig.Registration)
	}
	switch c.SMTPConfig.TLS {
	case "starttls", "tls", "none":
	default:
		return fmt.Errorf("SMTP_TLS must be starttls, tls or none, got %q", c.SMTPConfig.TLS)
	}
	if _, err := c.HTTPConfig.TrustedProxyPrefixes(); err != nil {
		return err
	}
	t := c.TokenConfig
	if t.AccessTokenTTL <= 0 || t.RefreshTokenTTL <= 0 || t.VoiceTokenTTL <= 0 || t.SessionMaxAge <= 0 || t.KeyRotation <= 0 {
		return errors.New("token TTLs and KEY_ROTATION must be positive")
	}
	if t.KeyPublishLead < 0 {
		return errors.New("KEY_PUBLISH_LEAD must not be negative")
	}
	return nil
}

// TrustedProxyPrefixes parses TRUSTED_PROXIES.
func (c HTTPConfig) TrustedProxyPrefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range SplitList(c.TrustedProxies) {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: %q is not an IP or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// SplitList splits a comma/space-separated env value.
func SplitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
}
