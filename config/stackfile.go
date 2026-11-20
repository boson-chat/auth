package config

import (
	"bytes"
	"fmt"
	netmail "net/mail"
	"net/url"
	"strings"

	"github.com/boson-chat/auth/internal/configfile"
	"gopkg.in/yaml.v3"
)

// The auth service's part of the stack config file (BOSON_CONFIG, see
// internal/configfile): the `network:` and `auth:` sections. A key that is
// set wins over the env value; an absent key falls back to env, then the
// built-in default. The branding: section and auth.email are in branding.go.
//
//	network:
//	  name: Boson                   # SITE_NAME
//	auth:
//	  registration: open            # REGISTRATION
//	  require_email_verification: true
//	  guest_access: true
//	  guest_voice: false
//	  channel_creation: registered
//	  voice_channel_creation: founders
//	  channel_auto_register: true
//	  channel_expiry_days: 0
//	  cors_allowed_origins: [https://app.example.com]   # CORS_ALLOWED_ORIGINS
//	  smtp: { host: smtp.example.com, port: 587, from: "Boson <hi@example.com>", tls: starttls }
//	files:
//	  enabled: true                 # FILES_ENABLED; only this key is auth's (files_url)
//
// SMTP_USER / SMTP_PASSWORD and every other secret stay in the env.

// FileConfig holds the keys set in the file; nil / unset means "not in the file".
type FileConfig struct {
	NetworkName *string

	Registration             *string
	RequireEmailVerification *bool
	GuestAccess              *bool
	GuestVoice               *bool
	ChannelCreation          *string
	VoiceChannelCreation     *string
	ChannelAutoRegister      *bool
	ChannelExpiryDays        *int

	CORSAllowedOrigins    []string
	CORSAllowedOriginsSet bool

	SMTPHost *string
	SMTPPort *int
	SMTPFrom *string
	SMTPTLS  *string

	// FilesEnabled is files.enabled (the rest of files: belongs to the
	// files service).
	FilesEnabled *bool

	// RolesChannelsAutojoin / RolesChannelsRejoin are roles.channels.autojoin
	// and roles.channels.rejoin.
	RolesChannelsAutojoin *bool
	RolesChannelsRejoin   *string

	// Branding is the branding: section; nil when absent.
	Branding *BrandingConfig
	// Email is auth.email; nil when absent (Boson's built-in emails).
	Email *EmailConfig

	// Unknown lists keys of our sections this version doesn't know (logged).
	Unknown []string
}

// Keys of the file, as reported in restart_required / audit.
const (
	KeyNetworkName              = "network.name"
	KeyRegistration             = "auth.registration"
	KeyRequireEmailVerification = "auth.require_email_verification"
	KeyGuestAccess              = "auth.guest_access"
	KeyGuestVoice               = "auth.guest_voice"
	KeyChannelCreation          = "auth.channel_creation"
	KeyVoiceChannelCreation     = "auth.voice_channel_creation"
	KeyChannelAutoRegister      = "auth.channel_auto_register"
	KeyChannelExpiryDays        = "auth.channel_expiry_days"
	KeyCORSAllowedOrigins       = "auth.cors_allowed_origins"
	KeySMTPHost                 = "auth.smtp.host"
	KeySMTPPort                 = "auth.smtp.port"
	KeySMTPFrom                 = "auth.smtp.from"
	KeySMTPTLS                  = "auth.smtp.tls"
	KeyFilesEnabled             = "files.enabled"
	KeyRolesChannelsAutojoin    = "roles.channels.autojoin"
	KeyRolesChannelsRejoin      = "roles.channels.rejoin"
)

// MaxSiteNameLen bounds network.name.
const MaxSiteNameLen = 100

// LoadFileConfig decodes and validates the network and auth sections.
// Errors carry the line and column of the offending value.
func LoadFileConfig(doc *configfile.Document) (FileConfig, error) {
	var f FileConfig
	network, err := doc.Section("network")
	if err != nil {
		return f, err
	}
	auth, err := doc.Section("auth")
	if err != nil {
		return f, err
	}
	smtp, err := auth.Sub("smtp")
	if err != nil {
		return f, err
	}
	files, err := doc.Section("files")
	if err != nil {
		return f, err
	}
	rolesSection, err := doc.Section("roles")
	if err != nil {
		return f, err
	}
	roleChannels, err := rolesSection.Sub("channels")
	if err != nil {
		return f, err
	}
	str := func(s *configfile.Section, key string, dst **string, check func(string) string) error {
		v, err := s.String(key)
		if err != nil || v == nil {
			return err
		}
		*v = strings.TrimSpace(*v)
		if check != nil {
			if msg := check(*v); msg != "" {
				return s.Errorf(key, "%s", msg)
			}
		}
		*dst = v
		return nil
	}
	boolean := func(key string, dst **bool) error {
		v, err := auth.Bool(key)
		*dst = v
		return err
	}
	oneOf := func(valid func(string) bool, choices string) func(string) string {
		return func(v string) string {
			if !valid(v) {
				return fmt.Sprintf("must be %s, got %q", choices, v)
			}
			return ""
		}
	}
	steps := []func() error{
		func() error {
			return str(network, "name", &f.NetworkName, func(v string) string {
				if v == "" {
					return "can't be empty (remove the key to use SITE_NAME)"
				}
				if len([]rune(v)) > MaxSiteNameLen {
					return fmt.Sprintf("must be at most %d characters", MaxSiteNameLen)
				}
				return ""
			})
		},
		func() error {
			return str(auth, "registration", &f.Registration, oneOf(ValidRegistration, "open, invite or closed"))
		},
		func() error { return boolean("require_email_verification", &f.RequireEmailVerification) },
		func() error { return boolean("guest_access", &f.GuestAccess) },
		func() error { return boolean("guest_voice", &f.GuestVoice) },
		func() error {
			return str(auth, "channel_creation", &f.ChannelCreation, oneOf(ValidChannelCreation, "registered or admins"))
		},
		func() error {
			return str(auth, "voice_channel_creation", &f.VoiceChannelCreation, oneOf(ValidVoiceChannelCreation, "admins, founders or registered"))
		},
		func() error { return boolean("channel_auto_register", &f.ChannelAutoRegister) },
		func() error {
			v, err := auth.Int("channel_expiry_days")
			if err != nil || v == nil {
				return err
			}
			if !ValidChannelExpiryDays(*v) {
				return auth.Errorf("channel_expiry_days", "must be between 0 and %d (0 = never expire), got %d", MaxChannelExpiryDays, *v)
			}
			f.ChannelExpiryDays = v
			return nil
		},
		func() error {
			list, set, err := auth.Strings("cors_allowed_origins")
			if err != nil || !set {
				return err
			}
			out := make([]string, 0, len(list))
			for i, o := range list {
				o = strings.TrimRight(strings.TrimSpace(o), "/")
				if !validOrigin(o) {
					return configfile.At(auth.ItemNode("cors_allowed_origins", i),
						"auth.cors_allowed_origins: %q is not an origin (scheme://host[:port], no path)", list[i])
				}
				out = append(out, o)
			}
			f.CORSAllowedOrigins, f.CORSAllowedOriginsSet = out, true
			return nil
		},
		func() error { return str(smtp, "host", &f.SMTPHost, nil) },
		func() error {
			v, err := smtp.Int("port")
			if err != nil || v == nil {
				return err
			}
			if *v < 1 || *v > 65535 {
				return smtp.Errorf("port", "must be between 1 and 65535, got %d", *v)
			}
			f.SMTPPort = v
			return nil
		},
		func() error {
			return str(smtp, "from", &f.SMTPFrom, func(v string) string {
				if _, err := netmail.ParseAddress(v); err != nil {
					return fmt.Sprintf("must be an email address such as \"Boson <hi@example.com>\", got %q", v)
				}
				return ""
			})
		},
		func() error {
			v, err := files.Bool("enabled")
			f.FilesEnabled = v
			return err
		},
		func() error {
			v, err := roleChannels.Bool("autojoin")
			f.RolesChannelsAutojoin = v
			return err
		},
		func() error {
			return str(roleChannels, "rejoin", &f.RolesChannelsRejoin, oneOf(ValidRejoin, "login or once"))
		},
		func() error {
			return str(smtp, "tls", &f.SMTPTLS, oneOf(func(v string) bool { return v == "starttls" || v == "tls" || v == "none" }, "starttls, tls or none"))
		},
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return FileConfig{}, err
		}
	}
	email, unknownEmail, err := loadEmail(auth)
	if err != nil {
		return FileConfig{}, err
	}
	branding, unknownBranding, err := loadBranding(doc)
	if err != nil {
		return FileConfig{}, err
	}
	f.Email, f.Branding = email, branding
	f.Unknown = append(f.Unknown, unknownEmail...)
	f.Unknown = append(f.Unknown, unknownBranding...)
	if smtp.Has("user") || smtp.Has("password") {
		return FileConfig{}, smtp.Errorf(firstSet(smtp, "password", "user"),
			"SMTP credentials are secrets: set SMTP_USER / SMTP_PASSWORD in .env, not in the config file")
	}
	f.Unknown = append(f.Unknown, network.Unknown("name")...)
	f.Unknown = append(f.Unknown, auth.Unknown("registration", "require_email_verification", "guest_access", "guest_voice", "channel_creation",
		"voice_channel_creation", "channel_auto_register", "channel_expiry_days", "cors_allowed_origins", "smtp", "email")...)
	f.Unknown = append(f.Unknown, smtp.Unknown("host", "port", "from", "tls")...)
	f.Unknown = append(f.Unknown, rolesSection.Unknown("channels")...)
	f.Unknown = append(f.Unknown, roleChannels.Unknown("autojoin", "rejoin")...)
	return f, nil
}

func firstSet(s *configfile.Section, keys ...string) string {
	for _, k := range keys {
		if s.Has(k) {
			return k
		}
	}
	return keys[0]
}

func validOrigin(o string) bool {
	u, err := url.Parse(o)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" &&
		(u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

// Flatten maps every key set in the file to its value (audit diffs).
func (f FileConfig) Flatten() map[string]any {
	m := map[string]any{}
	put := func(key string, set bool, v any) {
		if set {
			m[key] = v
		}
	}
	put(KeyNetworkName, f.NetworkName != nil, deref(f.NetworkName))
	put(KeyRegistration, f.Registration != nil, deref(f.Registration))
	put(KeyRequireEmailVerification, f.RequireEmailVerification != nil, deref(f.RequireEmailVerification))
	put(KeyGuestAccess, f.GuestAccess != nil, deref(f.GuestAccess))
	put(KeyGuestVoice, f.GuestVoice != nil, deref(f.GuestVoice))
	put(KeyChannelCreation, f.ChannelCreation != nil, deref(f.ChannelCreation))
	put(KeyVoiceChannelCreation, f.VoiceChannelCreation != nil, deref(f.VoiceChannelCreation))
	put(KeyChannelAutoRegister, f.ChannelAutoRegister != nil, deref(f.ChannelAutoRegister))
	put(KeyChannelExpiryDays, f.ChannelExpiryDays != nil, deref(f.ChannelExpiryDays))
	put(KeyCORSAllowedOrigins, f.CORSAllowedOriginsSet, f.CORSAllowedOrigins)
	put(KeySMTPHost, f.SMTPHost != nil, deref(f.SMTPHost))
	put(KeySMTPPort, f.SMTPPort != nil, deref(f.SMTPPort))
	put(KeySMTPFrom, f.SMTPFrom != nil, deref(f.SMTPFrom))
	put(KeySMTPTLS, f.SMTPTLS != nil, deref(f.SMTPTLS))
	put(KeyFilesEnabled, f.FilesEnabled != nil, deref(f.FilesEnabled))
	put(KeyRolesChannelsAutojoin, f.RolesChannelsAutojoin != nil, deref(f.RolesChannelsAutojoin))
	put(KeyRolesChannelsRejoin, f.RolesChannelsRejoin != nil, deref(f.RolesChannelsRejoin))
	f.flattenBranding(m)
	return m
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// WithFile returns c with the file's values applied over the env values
// (precedence: file > env > default). c is the env-only config.
func (c Config) WithFile(f FileConfig) Config {
	set := func(dst *string, v *string) {
		if v != nil {
			*dst = *v
		}
	}
	set(&c.AppConfig.SiteName, f.NetworkName)
	a := &c.AccountConfig
	set(&a.Registration, f.Registration)
	set(&a.ChannelCreation, f.ChannelCreation)
	set(&a.VoiceChannelCreation, f.VoiceChannelCreation)
	for dst, v := range map[*bool]*bool{
		&a.RequireEmailVerification: f.RequireEmailVerification, &a.GuestAccess: f.GuestAccess, &a.GuestVoice: f.GuestVoice, &a.ChannelAutoRegister: f.ChannelAutoRegister,
	} {
		if v != nil {
			*dst = *v
		}
	}
	if f.ChannelExpiryDays != nil {
		a.ChannelExpiryDays = *f.ChannelExpiryDays
	}
	if f.CORSAllowedOriginsSet {
		c.HTTPConfig.CORSAllowedOrigins = strings.Join(f.CORSAllowedOrigins, ",")
	}
	set(&c.SMTPConfig.Host, f.SMTPHost)
	set(&c.SMTPConfig.From, f.SMTPFrom)
	set(&c.SMTPConfig.TLS, f.SMTPTLS)
	if f.SMTPPort != nil {
		c.SMTPConfig.Port = *f.SMTPPort
	}
	if f.FilesEnabled != nil {
		c.FilesConfig.Enabled = *f.FilesEnabled
	}
	if f.RolesChannelsAutojoin != nil {
		c.RolesConfig.ChannelsAutojoin = *f.RolesChannelsAutojoin
	}
	set(&c.RolesConfig.ChannelsRejoin, f.RolesChannelsRejoin)
	return c
}

// ExportFile renders the network: and auth: sections for the stack config
// file from c (env values with the database's network settings applied).
// corsSet: CORS_ALLOWED_ORIGINS was set explicitly (otherwise the origin
// derived from APP_URL is left to the default).
func ExportFile(c Config, corsSet bool) ([]byte, error) {
	a := c.AccountConfig
	auth := []any{
		"registration", a.Registration,
		"require_email_verification", a.RequireEmailVerification,
		"guest_access", a.GuestAccess,
		"guest_voice", a.GuestVoice,
		"channel_creation", a.ChannelCreation,
		"voice_channel_creation", a.VoiceChannelCreation,
		"channel_auto_register", a.ChannelAutoRegister,
		"channel_expiry_days", a.ChannelExpiryDays,
	}
	if corsSet {
		auth = append(auth, "cors_allowed_origins", nonNil(SplitList(c.HTTPConfig.CORSAllowedOrigins)))
	}
	sm := c.SMTPConfig
	var smtp []any
	if sm.Host != "" {
		smtp = append(smtp, "host", sm.Host)
	}
	smtp = append(smtp, "port", sm.Port, "from", sm.From, "tls", sm.TLS)
	auth = append(auth, "smtp", mapping(smtp...))
	root := mapping(
		"network", mapping("name", c.AppConfig.SiteName),
		"auth", mapping(auth...),
	)
	root.Content[0].HeadComment = "Exported by `auth export-config` from the env and the network_settings table.\n" +
		"Merge into config/boson.yaml; SMTP_USER / SMTP_PASSWORD stay in .env."
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}); err != nil {
		return nil, err
	}
	return buf.Bytes(), enc.Close()
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// mapping builds an ordered YAML mapping from key, value pairs.
func mapping(kv ...any) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode}
	for i := 0; i+1 < len(kv); i += 2 {
		var v *yaml.Node
		switch x := kv[i+1].(type) {
		case *yaml.Node:
			v = x
		default:
			v = &yaml.Node{}
			_ = v.Encode(x)
		}
		m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: kv[i].(string)}, v)
	}
	return m
}
