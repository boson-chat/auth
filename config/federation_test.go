package config

import (
	"strings"
	"testing"
)

func TestFederationDomain(t *testing.T) {
	for issuer, want := range map[string]string{
		"https://auth.boson.chat":       "boson.chat",
		"https://auth.chat.example.org": "chat.example.org",
		"https://login.example.org":     "login.example.org",
		"https://auth.localhost":        "auth.localhost",
		"http://localhost:8080":         "",
	} {
		c := Config{TokenConfig: TokenConfig{Issuer: issuer}}
		if got := c.FederationDomain(); got != want {
			t.Errorf("%s: %q, want %q", issuer, got, want)
		}
	}
	c := Config{TokenConfig: TokenConfig{Issuer: "https://auth.boson.chat"}, FederationConfig: FederationConfig{Domain: "Example.ORG"}}
	if c.FederationDomain() != "example.org" {
		t.Fatal(c.FederationDomain())
	}
}

func TestDomainLists(t *testing.T) {
	l, err := ParseDomainList([]string{" Boson.Chat. ", "*.example.org", "boson.chat", ""})
	if err != nil || len(l) != 2 || l[0] != "boson.chat" || l[1] != "*.example.org" {
		t.Fatalf("%v %v", l, err)
	}
	for _, bad := range []string{"*.org", "localhost", "a b.org", "-x.org", "x.org:443", "https://x.org"} {
		if _, err := ParseDomainList([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for d, want := range map[string]bool{
		"boson.chat": true, "x.boson.chat": false, "example.org": true, "a.b.example.org": true,
		"notexample.org": false, "evil.org": false,
	} {
		if got := DomainListMatches(l, d); got != want {
			t.Errorf("%s: %v", d, got)
		}
	}
}

func TestParseSize(t *testing.T) {
	for s, want := range map[string]int64{"1024": 1024, "1GB": 1e9, "500 MB": 5e8, "2GiB": 2 << 30, "1.5KB": 1500, "10kib": 10240} {
		if got, err := ParseSize(s); err != nil || got != want {
			t.Errorf("%s: %d %v", s, got, err)
		}
	}
	for _, s := range []string{"", "GB", "1PB", "x1"} {
		if _, err := ParseSize(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestValidateFederation(t *testing.T) {
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.FederationConfig.Mode != FederationDirectory || c.FederationConfig.DirectoryURL != DefaultDirectoryURL || !c.FederationConfig.RemoteVoice {
		t.Fatalf("defaults: %+v", c.FederationConfig)
	}
	for name, mut := range map[string]func(*Config){
		"mode":      func(c *Config) { c.FederationConfig.Mode = "sometimes" },
		"allow":     func(c *Config) { c.FederationConfig.Allow = "not a domain" },
		"block":     func(c *Config) { c.FederationConfig.Block = "*.com" },
		"directory": func(c *Config) { c.FederationConfig.DirectoryURL = "http://directory.example.org" },
		"domain":    func(c *Config) { c.FederationConfig.Domain = "localhost" },
		"quota":     func(c *Config) { c.FederationConfig.RemoteUploadQuota = "lots" },
		"files":     func(c *Config) { c.FilesInternalConfig.URL = "files:3001" },
	} {
		cc := c
		mut(&cc)
		if cc.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c.FederationConfig.Allow, c.FederationConfig.RemoteUploadQuota = "boson.chat, *.example.org", "2GB"
	c.FederationConfig.DirectoryURL = "http://127.0.0.1:9000"
	c.FederationConfig.AllowHTTP = true
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestFederationFileSection(t *testing.T) {
	f, err := loadFile(t, `version: 1
auth:
  federation:
    mode: allowlist
    allow: [Boson.Chat, "*.example.org"]
    block: []
    directory_url: https://dir.example.org/
    remote_upload_quota: 1GB
    remote_voice: false
`)
	if err != nil {
		t.Fatal(err)
	}
	ff := f.Federation
	if *ff.Mode != "allowlist" || strings.Join(ff.Allow, ",") != "boson.chat,*.example.org" || !ff.BlockSet || len(ff.Block) != 0 ||
		*ff.DirectoryURL != "https://dir.example.org" || *ff.RemoteUploadQuota != "1GB" || *ff.RemoteVoice {
		t.Fatalf("%+v", ff)
	}
	if got := strings.Join(ff.Fields(), ","); got != "mode,allow,block,directory_url,remote_upload_quota,remote_voice" {
		t.Fatal(got)
	}
	c := Config{FederationConfig: FederationConfig{Mode: "open", Block: "x.org", RemoteVoice: true}}.WithFile(f)
	if c.FederationConfig.Mode != "allowlist" || c.FederationConfig.Allow != "boson.chat,*.example.org" || c.FederationConfig.Block != "" || c.FederationConfig.RemoteVoice {
		t.Fatalf("%+v", c.FederationConfig)
	}
	if m := f.Flatten(); m[KeyFederationMode] != "allowlist" || m[KeyFederationRemoteVoice] != false {
		t.Fatalf("%v", m)
	}
	for _, bad := range []string{
		"mode: sometimes", "allow: [not a domain]", "directory_url: http://x.org", "remote_upload_quota: lots", "remote_voice: maybe",
	} {
		if _, err := loadFile(t, "version: 1\nauth:\n  federation:\n    "+bad+"\n"); err == nil || !strings.Contains(err.Error(), "line") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	f, _ = loadFile(t, "version: 1\nauth:\n  registration: open\n")
	if len(f.Federation.Fields()) != 0 {
		t.Fatal("fields without a section")
	}
}
