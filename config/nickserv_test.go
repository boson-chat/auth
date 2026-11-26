package config

import (
	"strings"
	"testing"
	"time"
)

func validNickServ() NickServConfig {
	return NickServConfig{
		Strategy: StrategyAnopeRPC, RPCURL: "http://127.0.0.1:8080/jsonrpc", RPCToken: "t",
		IRCTLS: true, IRCNickPrefix: "bsn", ServiceNick: "NickServ", Timeout: 10 * time.Second, MaxConcurrent: 8,
		LinkExisting: LinkExistingUnclaimed, RateAccountBurst: 5, RateAccountPerMinute: 2, RateIPBurst: 10, RateIPPerMinute: 5,
		LockoutThreshold: 10, LockoutIPThreshold: 30, LockoutWindow: 15 * time.Minute, LockoutDuration: 15 * time.Minute,
	}
}

func TestNickServValidate(t *testing.T) {
	if err := validNickServ().Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		mut  func(*NickServConfig)
		want string
	}{
		"no strategy":         {func(c *NickServConfig) { c.Strategy = "" }, "needs NICKSERV_STRATEGY"},
		"bad strategy":        {func(c *NickServConfig) { c.Strategy = "ldap" }, "NICKSERV_STRATEGY must be"},
		"http to remote":      {func(c *NickServConfig) { c.RPCURL = "http://services.example.org/jsonrpc" }, "plain http"},
		"anope without token": {func(c *NickServConfig) { c.RPCToken = "" }, "NICKSERV_RPC_TOKEN"},
		"no irc addr":         {func(c *NickServConfig) { c.Strategy = StrategySASL }, "NICKSERV_IRC_ADDR"},
		"plaintext irc remote": {func(c *NickServConfig) {
			c.Strategy, c.IRCAddr, c.IRCTLS = StrategyIdentify, "irc.example.org:6667", false
		}, "clear text"},
		"bad pin":       {func(c *NickServConfig) { c.TLSPins = "abc" }, "NICKSERV_TLS_PIN_SHA256"},
		"bad pattern":   {func(c *NickServConfig) { c.IdentifySuccess = "([" }, "NICKSERV_IDENTIFY_SUCCESS"},
		"bad link mode": {func(c *NickServConfig) { c.LinkExisting = "yes" }, "NICKSERV_LINK_EXISTING"},
		"missing CA":    {func(c *NickServConfig) { c.TLSCAFile = "/nonexistent/ca.pem" }, "NICKSERV_TLS_CA_FILE"},
		"service nick w/ space": {func(c *NickServConfig) {
			c.Strategy, c.IRCAddr, c.ServiceNick = StrategyIdentify, "irc:6697", "Nick Serv"
		}, "spaces"},
		"bad services": {func(c *NickServConfig) { c.Services = "epona" }, "NICKSERV_SERVICES"},
	}
	for name, tc := range cases {
		c := validNickServ()
		tc.mut(&c)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// Allowed: http to loopback, plaintext with the explicit opt-in.
	c := validNickServ()
	c.RPCURL = "http://anope:8080/jsonrpc"
	c.AllowPlaintext = true
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c = validNickServ()
	c.Strategy, c.IRCAddr, c.IRCTLS = StrategyIdentify, "localhost:6667", false
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParsePinsAndPatterns(t *testing.T) {
	hex := strings.Repeat("0a", 32)
	pins, err := ParsePins(hex + ", sha256/" + "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo=")
	if err != nil || len(pins) != 2 || pins[0][0] != 0x0a || pins[1][0] != 0x0a {
		t.Fatalf("%v %v", pins, err)
	}
	p, err := ParsePatterns("^a$\n\n  ^b$  ")
	if err != nil || len(p) != 2 {
		t.Fatalf("%v %v", p, err)
	}
	p, err = ParsePatterns(`["^x\\.$"]`)
	if err != nil || len(p) != 1 || !p[0].MatchString("x.") {
		t.Fatalf("%v %v", p, err)
	}
}

func TestAccountBackendDefault(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Skip("env not loadable here:", err)
	}
	if cfg.AccountsConfig.Backend != AccountBackendLocal || cfg.AccountsConfig.NickServ() {
		t.Fatalf("default backend = %q", cfg.AccountsConfig.Backend)
	}
}
