package config

import (
	"strings"
	"testing"
	"time"
)

func TestBridgeConfigValidate(t *testing.T) {
	ok := BridgeConfig{APIURL: "http://evrd-links:8098", Token: "t", PollInterval: time.Second, ReconcileInterval: 10 * time.Minute,
		RetryMin: 2 * time.Second, RetryMax: 5 * time.Minute, Timeout: 10 * time.Second}
	if err := ok.Validate(); err != nil || !ok.Enabled() {
		t.Fatalf("valid config: %v", err)
	}
	if err := (BridgeConfig{}).Validate(); err != nil || (BridgeConfig{}).Enabled() {
		t.Fatalf("unset: %v", err)
	}
	for name, c := range map[string]func(*BridgeConfig){
		"only the URL":   func(c *BridgeConfig) { c.Token = "" },
		"only the token": func(c *BridgeConfig) { c.APIURL = "" },
		"not http":       func(c *BridgeConfig) { c.APIURL = "evrd-links:8098" },
		"bad method":     func(c *BridgeConfig) { c.NickServMethod = "identify" },
		"retry range":    func(c *BridgeConfig) { c.RetryMax = time.Second },
		"no poll":        func(c *BridgeConfig) { c.PollInterval = 0 },
	} {
		b := ok
		c(&b)
		if err := b.Validate(); err == nil || !strings.Contains(err.Error(), "BRIDGE_") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
