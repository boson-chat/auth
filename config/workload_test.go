package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

const wlToken = "0123456789abcdef0123456789abcdef"

func TestWorkloadDefaultsOff(t *testing.T) {
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	w := c.WorkloadConfig
	if w.Enabled() || w.TokenTTL != 5*time.Minute || w.KeyRotation != 720*time.Hour || w.KeyPublishLead != time.Hour {
		t.Fatalf("defaults: %+v", w)
	}
	if list, err := w.Workloads(); err != nil || len(list) != 0 {
		t.Fatalf("workloads %v %v", list, err)
	}
}

func TestWorkloadFromEnv(t *testing.T) {
	t.Setenv("WORKLOAD_IDENTITIES", "pushrelay:boson-pushrelay")
	t.Setenv("WORKLOAD_TOKEN_PUSHRELAY", wlToken)
	t.Setenv("WORKLOAD_TOKEN_TTL", "10m")
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	list, err := c.WorkloadConfig.Workloads()
	if err != nil || len(list) != 1 {
		t.Fatalf("workloads %v %v", list, err)
	}
	w := list[0]
	if w.Name != "pushrelay" || w.Subject() != "service:pushrelay" || w.Token != wlToken || len(w.Audiences) != 1 || w.Audiences[0] != "boson-pushrelay" {
		t.Fatalf("workload %+v", w)
	}
}

func TestWorkloadParse(t *testing.T) {
	c := WorkloadConfig{
		Identities: "pushrelay:boson-pushrelay, pushrelay:other,push-relay2:x pushrelay:other",
		Getenv:     env(map[string]string{"WORKLOAD_TOKEN_PUSHRELAY": "a", "WORKLOAD_TOKEN_PUSH_RELAY2": "b"}),
	}
	list, err := c.Workloads()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || strings.Join(list[0].Audiences, ",") != "boson-pushrelay,other" || list[1].Name != "push-relay2" || list[1].Token != "b" {
		t.Fatalf("parsed %+v", list)
	}
	for _, bad := range []string{"pushrelay", "pushrelay:", ":aud", "Push:aud", "a b:aud", "push_relay:a,push-relay:b"} {
		if _, err := (WorkloadConfig{Identities: bad, Getenv: env(nil)}).Workloads(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestWorkloadValidate(t *testing.T) {
	ok := WorkloadConfig{Identities: "pushrelay:boson-pushrelay", TokenTTL: 5 * time.Minute, KeyRotation: time.Hour,
		Getenv: env(map[string]string{"WORKLOAD_TOKEN_PUSHRELAY": wlToken})}
	if err := ok.Validate("internal-token"); err != nil {
		t.Fatal(err)
	}
	if err := (WorkloadConfig{}).Validate(); err != nil {
		t.Fatalf("off must validate: %v", err)
	}
	cases := map[string]func(*WorkloadConfig){
		"ttl over 10m": func(c *WorkloadConfig) { c.TokenTTL = 11 * time.Minute },
		"ttl zero":     func(c *WorkloadConfig) { c.TokenTTL = 0 },
		"no rotation":  func(c *WorkloadConfig) { c.KeyRotation = 0 },
		"no token":     func(c *WorkloadConfig) { c.Getenv = env(nil) },
		"short token":  func(c *WorkloadConfig) { c.Getenv = env(map[string]string{"WORKLOAD_TOKEN_PUSHRELAY": "short"}) },
		"reserved": func(c *WorkloadConfig) {
			c.Getenv = env(map[string]string{"WORKLOAD_TOKEN_PUSHRELAY": "internal-token-xxxxxxxx"})
		},
		"shared token": func(c *WorkloadConfig) {
			c.Identities += ",other:aud"
			c.Getenv = env(map[string]string{"WORKLOAD_TOKEN_PUSHRELAY": wlToken, "WORKLOAD_TOKEN_OTHER": wlToken})
		},
	}
	for name, mutate := range cases {
		c := ok
		mutate(&c)
		if err := c.Validate("internal-token-xxxxxxxx"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Config.Validate passes INTERNAL_API_TOKEN as reserved.
func TestWorkloadTokenMustDifferFromInternalToken(t *testing.T) {
	t.Setenv("WORKLOAD_IDENTITIES", "pushrelay:boson-pushrelay")
	t.Setenv("WORKLOAD_TOKEN_PUSHRELAY", wlToken)
	t.Setenv("INTERNAL_API_TOKEN", wlToken)
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "INTERNAL_API_TOKEN") {
		t.Fatalf("err = %v", err)
	}
}
