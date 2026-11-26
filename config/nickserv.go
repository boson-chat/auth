package config

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Account backends (ACCOUNT_BACKEND).
const (
	// AccountBackendLocal: auth owns accounts and passwords (the default).
	AccountBackendLocal = "local"
	// AccountBackendNickServ: accounts are the IRC network's NickServ
	// accounts; auth verifies passwords with the services and keeps a
	// linked local record (roles, profile, friends) without a password.
	AccountBackendNickServ = "nickserv"
)

// NickServ verification strategies (NICKSERV_STRATEGY).
const (
	// StrategyAnopeRPC: Anope 2.1 JSON-RPC (anope.checkCredentials).
	StrategyAnopeRPC = "anope_rpc"
	// StrategyAthemeJSONRPC / StrategyAthemeXMLRPC: Atheme's atheme.login
	// over JSON-RPC or XML-RPC. Also registers accounts.
	StrategyAthemeJSONRPC = "atheme_jsonrpc"
	StrategyAthemeXMLRPC  = "atheme_xmlrpc"
	// StrategySASL: SASL PLAIN on a short-lived IRC connection.
	StrategySASL = "sasl"
	// StrategyIdentify: /msg NickServ IDENTIFY on a short-lived IRC
	// connection (servers without SASL, e.g. ngircd).
	StrategyIdentify = "identify"
)

// NICKSERV_LINK_EXISTING values.
const (
	LinkExistingNone      = "none"
	LinkExistingUnclaimed = "unclaimed"
	LinkExistingAll       = "all"
)

// Services packages (NICKSERV_SERVICES), for the IDENTIFY reply patterns.
const (
	ServicesAnope  = "anope"
	ServicesAtheme = "atheme"
)

// AccountsConfig selects where accounts live.
type AccountsConfig struct {
	// local (default) | nickserv. Changing it needs a restart.
	Backend string `default:"local" env:"ACCOUNT_BACKEND"`
}

// NickServ reports whether the NickServ account backend is on.
func (c AccountsConfig) NickServ() bool { return c.Backend == AccountBackendNickServ }

// NickServConfig is the NickServ account backend (ACCOUNT_BACKEND=nickserv).
// See docs/nickserv.md.
type NickServConfig struct {
	// anope_rpc | atheme_jsonrpc | atheme_xmlrpc | sasl | identify
	Strategy string `env:"NICKSERV_STRATEGY"`
	// anope | atheme: which services package runs on the network. Picks
	// the IDENTIFY reply patterns; defaults from the strategy (anope for
	// sasl / identify).
	Services string `env:"NICKSERV_SERVICES"`

	// RPC strategies: the services' JSON-RPC / XML-RPC endpoint, e.g.
	// http://127.0.0.1:8080/jsonrpc (Anope httpd + jsonrpc, Atheme misc/httpd).
	RPCURL string `env:"NICKSERV_RPC_URL"`
	// Anope's jsonrpc token (token { token = "..." }), sent as Bearer
	// base64(token). Needs anope.checkCredentials (and anope.account for
	// the email). Unused by Atheme.
	RPCToken string `env:"NICKSERV_RPC_TOKEN"`

	// sasl / identify: the IRC server, host:port.
	IRCAddr string `env:"NICKSERV_IRC_ADDR"`
	// TLS to the IRC server (default on). Off sends passwords in clear
	// text and needs NICKSERV_ALLOW_PLAINTEXT unless the server is on loopback.
	IRCTLS bool `default:"true" env:"NICKSERV_IRC_TLS"`
	// Server password (PASS) for the check connection, if the server wants one.
	IRCPassword string `env:"NICKSERV_IRC_PASSWORD"`
	// Nick prefix of the check connection: <prefix><6 hex>. Keep it short:
	// ngircd's default NICKLEN is 9.
	IRCNickPrefix string `default:"bsn" env:"NICKSERV_IRC_NICK_PREFIX"`

	// Allow http:// RPC URLs and IRC without TLS to non-loopback hosts
	// (e.g. a private Docker network). Passwords then cross that network
	// in clear text.
	AllowPlaintext bool `default:"false" env:"NICKSERV_ALLOW_PLAINTEXT"`
	// PEM file of the CA(s) the IRC / RPC server's certificate must chain
	// to, instead of the system roots.
	TLSCAFile string `env:"NICKSERV_TLS_CA_FILE"`
	// Comma-separated SHA-256 pins of the server certificate's public key
	// (SubjectPublicKeyInfo), hex or base64. With a pin and no CA file the
	// chain isn't checked, only the pin (self-signed IRC certificates).
	TLSPins string `env:"NICKSERV_TLS_PIN_SHA256"`
	// Name the certificate must be valid for; default the host of
	// NICKSERV_IRC_ADDR / NICKSERV_RPC_URL.
	TLSServerName string `env:"NICKSERV_TLS_SERVER_NAME"`

	// Deadline for one verification (connect, TLS, IRC registration, reply).
	Timeout time.Duration `default:"10s" env:"NICKSERV_TIMEOUT"`
	// At most this many verifications at once (IRC connections / RPC calls).
	MaxConcurrent int `default:"8" env:"NICKSERV_MAX_CONCURRENT"`

	// identify: who to message and who must answer.
	ServiceNick string `default:"NickServ" env:"NICKSERV_SERVICE_NICK"`
	// PRIVMSG target for IDENTIFY; default ServiceNick. NickServ@services.example.org
	// only reaches the real service.
	ServiceTarget string `env:"NICKSERV_SERVICE_TARGET"`
	// If set, the check WHOISes ServiceNick and only sends the password when
	// it is on this server (the services server name).
	ServicesServer string `env:"NICKSERV_SERVICES_SERVER"`
	// IDENTIFY reply patterns (Go regexps, one per line, or a JSON array),
	// matched against NickServ's notices with formatting stripped. Empty =
	// the NICKSERV_SERVICES defaults (docs/nickserv.md).
	IdentifySuccess string `env:"NICKSERV_IDENTIFY_SUCCESS"`
	IdentifyFailure string `env:"NICKSERV_IDENTIFY_FAILURE"`
	// Replies that refuse the login without saying the password is wrong
	// (suspended, too many sessions, ...): not counted towards the lockout.
	IdentifyRefused string `env:"NICKSERV_IDENTIFY_REFUSED"`

	// Boson sign-up registers a NickServ account when the strategy can
	// (atheme_*). False, or a strategy that can't: sign-up is off and
	// points users at IRC.
	Registration bool `default:"true" env:"NICKSERV_REGISTRATION"`
	// Shown when sign-up is off. Default: register with NickServ on IRC.
	SignupMessage string `env:"NICKSERV_SIGNUP_MESSAGE"`
	// What a first NickServ sign-in may do with an existing, not yet linked
	// local account of the same name: unclaimed (default) links it only
	// if it has no password and no SSO identity (an account an admin made
	// for that person, e.g. `auth user create --no-password --role owner`);
	// all also links accounts with a Boson password or SSO identity (a
	// network moving its own accounts to NickServ, trusting that the same
	// name is the same person); none never links (the sign-in is refused).
	LinkExisting string `default:"unclaimed" env:"NICKSERV_LINK_EXISTING"`
	// Keep the services' session (Atheme authcookie), encrypted, and end it
	// on logout. Off: log straight out of the services after the check.
	StoreSession bool `default:"true" env:"NICKSERV_STORE_SESSION"`

	// Verification attempts per account / per client IP (token buckets, per
	// replica), on top of the login endpoint's limits.
	RateAccountBurst     int     `default:"5" env:"NICKSERV_RATE_ACCOUNT_BURST"`
	RateAccountPerMinute float64 `default:"2" env:"NICKSERV_RATE_ACCOUNT_PER_MINUTE"`
	RateIPBurst          int     `default:"10" env:"NICKSERV_RATE_IP_BURST"`
	RateIPPerMinute      float64 `default:"5" env:"NICKSERV_RATE_IP_PER_MINUTE"`
	// Lockout (shared by replicas, in the database): this many failed
	// checks within LockoutWindow lock the account (or IP) for
	// LockoutDuration. 0 disables that lockout.
	LockoutThreshold   int           `default:"10" env:"NICKSERV_LOCKOUT_THRESHOLD"`
	LockoutIPThreshold int           `default:"30" env:"NICKSERV_LOCKOUT_IP_THRESHOLD"`
	LockoutWindow      time.Duration `default:"15m" env:"NICKSERV_LOCKOUT_WINDOW"`
	LockoutDuration    time.Duration `default:"15m" env:"NICKSERV_LOCKOUT_DURATION"`
}

// ServicesPackage is NICKSERV_SERVICES or its default for the strategy.
func (c NickServConfig) ServicesPackage() string {
	if c.Services != "" {
		return c.Services
	}
	if strings.HasPrefix(c.Strategy, "atheme") {
		return ServicesAtheme
	}
	return ServicesAnope
}

// Target is the IDENTIFY PRIVMSG target.
func (c NickServConfig) Target() string {
	if c.ServiceTarget != "" {
		return c.ServiceTarget
	}
	return c.ServiceNick
}

// UsesRPC reports whether the strategy talks to the services' RPC endpoint.
func (c NickServConfig) UsesRPC() bool {
	switch c.Strategy {
	case StrategyAnopeRPC, StrategyAthemeJSONRPC, StrategyAthemeXMLRPC:
		return true
	}
	return false
}

// CanRegister reports whether the strategy can register accounts.
func (c NickServConfig) CanRegister() bool {
	return c.Strategy == StrategyAthemeJSONRPC || c.Strategy == StrategyAthemeXMLRPC
}

// ParsePatterns splits a pattern list: a JSON array of strings, or one
// regexp per line. Blank lines are skipped.
func ParsePatterns(s string) ([]*regexp.Regexp, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var list []string
	if strings.HasPrefix(s, "[") {
		if err := json.Unmarshal([]byte(s), &list); err != nil {
			return nil, fmt.Errorf("not a JSON array of strings: %w", err)
		}
	} else {
		list = strings.Split(s, "\n")
	}
	var out []*regexp.Regexp
	for _, p := range list {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// ParsePins decodes NICKSERV_TLS_PIN_SHA256 (hex or base64 SHA-256 values).
func ParsePins(s string) ([][]byte, error) {
	var out [][]byte
	for _, p := range SplitList(s) {
		p = strings.TrimPrefix(strings.TrimPrefix(p, "sha256/"), "sha256:")
		var b []byte
		if h, err := hex.DecodeString(strings.ReplaceAll(p, ":", "")); err == nil && len(h) == 32 {
			b = h
		} else if d, err := base64.StdEncoding.DecodeString(p); err == nil && len(d) == 32 {
			b = d
		} else if d, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(p, "=")); err == nil && len(d) == 32 {
			b = d
		} else {
			return nil, fmt.Errorf("NICKSERV_TLS_PIN_SHA256: %q is not a SHA-256 in hex or base64", p)
		}
		out = append(out, b)
	}
	return out, nil
}

// loopbackHost reports whether host is localhost or a loopback IP.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && a.Unmap().IsLoopback()
}

// Validate checks the NickServ settings (only when the backend is on).
func (c NickServConfig) Validate() error {
	switch c.Strategy {
	case StrategyAnopeRPC, StrategyAthemeJSONRPC, StrategyAthemeXMLRPC, StrategySASL, StrategyIdentify:
	case "":
		return errors.New("ACCOUNT_BACKEND=nickserv needs NICKSERV_STRATEGY (anope_rpc, atheme_jsonrpc, atheme_xmlrpc, sasl or identify)")
	default:
		return fmt.Errorf("NICKSERV_STRATEGY must be anope_rpc, atheme_jsonrpc, atheme_xmlrpc, sasl or identify, got %q", c.Strategy)
	}
	switch c.ServicesPackage() {
	case ServicesAnope, ServicesAtheme:
	default:
		return fmt.Errorf("NICKSERV_SERVICES must be anope or atheme, got %q", c.Services)
	}
	if c.UsesRPC() {
		u, err := url.Parse(c.RPCURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return fmt.Errorf("NICKSERV_RPC_URL must be an http(s) URL such as http://127.0.0.1:8080/jsonrpc, got %q", c.RPCURL)
		}
		if u.Scheme == "http" && !c.AllowPlaintext && !loopbackHost(u.Hostname()) {
			return fmt.Errorf("NICKSERV_RPC_URL %q is plain http to a non-loopback host: passwords would cross the network unencrypted. Use https, or set NICKSERV_ALLOW_PLAINTEXT=true for a private network", c.RPCURL)
		}
		if c.Strategy == StrategyAnopeRPC && c.RPCToken == "" {
			return errors.New("NICKSERV_STRATEGY=anope_rpc needs NICKSERV_RPC_TOKEN (a jsonrpc token allowed anope.checkCredentials and anope.account)")
		}
	} else {
		host, port, err := net.SplitHostPort(c.IRCAddr)
		if err != nil || host == "" || port == "" {
			return fmt.Errorf("NICKSERV_IRC_ADDR must be host:port, got %q", c.IRCAddr)
		}
		if !c.IRCTLS && !c.AllowPlaintext && !loopbackHost(host) {
			return fmt.Errorf("NICKSERV_IRC_TLS=false to %q would send passwords in clear text. Use TLS, or set NICKSERV_ALLOW_PLAINTEXT=true for a private network", c.IRCAddr)
		}
		if p := c.IRCNickPrefix; p == "" || len(p) > 20 || !validNickPrefix(p) {
			return fmt.Errorf("NICKSERV_IRC_NICK_PREFIX must be 1-20 letters/digits starting with a letter, got %q", p)
		}
		if strings.ContainsAny(c.Target()+c.ServiceNick+c.ServicesServer+c.IRCPassword, " \r\n\x00") {
			return errors.New("NICKSERV_SERVICE_NICK, NICKSERV_SERVICE_TARGET, NICKSERV_SERVICES_SERVER and NICKSERV_IRC_PASSWORD must not contain spaces or line breaks")
		}
		if c.ServiceNick == "" {
			return errors.New("NICKSERV_SERVICE_NICK must not be empty")
		}
	}
	for name, v := range map[string]string{
		"NICKSERV_IDENTIFY_SUCCESS": c.IdentifySuccess, "NICKSERV_IDENTIFY_FAILURE": c.IdentifyFailure, "NICKSERV_IDENTIFY_REFUSED": c.IdentifyRefused,
	} {
		if _, err := ParsePatterns(v); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if _, err := ParsePins(c.TLSPins); err != nil {
		return err
	}
	if c.TLSCAFile != "" {
		pem, err := os.ReadFile(c.TLSCAFile)
		if err != nil {
			return fmt.Errorf("NICKSERV_TLS_CA_FILE: %w", err)
		}
		if !x509.NewCertPool().AppendCertsFromPEM(pem) {
			return fmt.Errorf("NICKSERV_TLS_CA_FILE %s has no PEM certificates", c.TLSCAFile)
		}
	}
	switch c.LinkExisting {
	case LinkExistingNone, LinkExistingUnclaimed, LinkExistingAll:
	default:
		return fmt.Errorf("NICKSERV_LINK_EXISTING must be none, unclaimed or all, got %q", c.LinkExisting)
	}
	if c.Timeout <= 0 || c.Timeout > 2*time.Minute {
		return errors.New("NICKSERV_TIMEOUT must be between 1ns and 2m")
	}
	if c.MaxConcurrent < 1 {
		return errors.New("NICKSERV_MAX_CONCURRENT must be at least 1")
	}
	if c.RateAccountBurst < 1 || c.RateAccountPerMinute <= 0 || c.RateIPBurst < 1 || c.RateIPPerMinute <= 0 {
		return errors.New("NICKSERV_RATE_* must be positive")
	}
	if c.LockoutThreshold < 0 || c.LockoutIPThreshold < 0 {
		return errors.New("NICKSERV_LOCKOUT_THRESHOLD and NICKSERV_LOCKOUT_IP_THRESHOLD must not be negative")
	}
	if (c.LockoutThreshold > 0 || c.LockoutIPThreshold > 0) && (c.LockoutWindow <= 0 || c.LockoutDuration <= 0) {
		return errors.New("NICKSERV_LOCKOUT_WINDOW and NICKSERV_LOCKOUT_DURATION must be positive")
	}
	return nil
}

func validNickPrefix(p string) bool {
	for i := 0; i < len(p); i++ {
		c := p[i]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !letter && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}
