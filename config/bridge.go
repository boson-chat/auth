package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Bridge login methods (BRIDGE_NICKSERV_METHOD): how the bridge logs a
// NickServ account in to the network's services.
const (
	BridgeMethodSASL     = "sasl"
	BridgeMethodNickServ = "nickserv"
	BridgeMethodAuto     = "auto"
)

// BridgeConfig is the evrd bridge (evrd's managed mode) that fronts an
// existing IRC server (docs/bridge.md). With BRIDGE_API_URL and
// BRIDGE_TOKEN set, auth gives every account its bridge account; unset,
// nothing happens.
type BridgeConfig struct {
	// The managed API, e.g. http://evrd-links:8098. Internal network only:
	// NickServ passwords cross it.
	APIURL string `env:"BRIDGE_API_URL"`
	// The managed API's bearer token (evrd's managed_token).
	Token string `env:"BRIDGE_TOKEN"`
	// How the bridge logs NickServ accounts in: sasl | nickserv | auto.
	// Default: nickserv with NICKSERV_STRATEGY=identify (the IRC server has
	// no SASL), else sasl.
	NickServMethod string `env:"BRIDGE_NICKSERV_METHOD"`
	// How often the outbox is checked for changes to push.
	PollInterval time.Duration `default:"1s" env:"BRIDGE_POLL_INTERVAL"`
	// A full sync (every account, and bridge accounts no Boson account has
	// are removed) at startup and this often; 0: only at startup and on
	// POST /internal/v1/bridge/reconcile.
	ReconcileInterval time.Duration `default:"10m" env:"BRIDGE_RECONCILE_INTERVAL"`
	// Retry backoff for failed pushes: doubles from RetryMin up to RetryMax.
	RetryMin time.Duration `default:"2s" env:"BRIDGE_RETRY_MIN"`
	RetryMax time.Duration `default:"5m" env:"BRIDGE_RETRY_MAX"`
	// Deadline for one call to the managed API.
	Timeout time.Duration `default:"10s" env:"BRIDGE_TIMEOUT"`
}

// Enabled reports whether bridge provisioning is on.
func (c BridgeConfig) Enabled() bool {
	return strings.TrimSpace(c.APIURL) != "" && strings.TrimSpace(c.Token) != ""
}

// Method is the bridge login method for NickServ accounts verified with strategy.
func (c BridgeConfig) Method(strategy string) string {
	if m := strings.ToLower(strings.TrimSpace(c.NickServMethod)); m != "" {
		return m
	}
	if strategy == StrategyIdentify {
		return BridgeMethodNickServ
	}
	return BridgeMethodSASL
}

// Validate checks the bridge settings (only when Enabled).
func (c BridgeConfig) Validate() error {
	if !c.Enabled() {
		if strings.TrimSpace(c.APIURL) != "" || strings.TrimSpace(c.Token) != "" {
			return errors.New("set both BRIDGE_API_URL and BRIDGE_TOKEN (or neither)")
		}
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(c.APIURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("BRIDGE_API_URL must be an http(s) URL such as http://evrd-links:8098, got %q", c.APIURL)
	}
	switch strings.ToLower(strings.TrimSpace(c.NickServMethod)) {
	case "", BridgeMethodSASL, BridgeMethodNickServ, BridgeMethodAuto:
	default:
		return fmt.Errorf("BRIDGE_NICKSERV_METHOD must be sasl, nickserv or auto, got %q", c.NickServMethod)
	}
	if c.PollInterval <= 0 || c.ReconcileInterval < 0 || c.RetryMin <= 0 || c.RetryMax < c.RetryMin || c.Timeout <= 0 {
		return errors.New("BRIDGE_POLL_INTERVAL, BRIDGE_RETRY_MIN and BRIDGE_TIMEOUT must be positive, BRIDGE_RETRY_MAX at least BRIDGE_RETRY_MIN and BRIDGE_RECONCILE_INTERVAL not negative")
	}
	return nil
}
