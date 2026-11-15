package integration

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
)

// writeConfig replaces the file the way the admin panel does (tmp + rename).
func writeConfig(t *testing.T, path, content string) {
	t.Helper()
	tmp := filepath.Join(filepath.Dir(path), ".boson.yaml.tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestConfigFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boson.yaml")
	writeConfig(t, path, `version: 1
network:
  name: File Net
auth:
  registration: closed
  guest_access: false
  channel_expiry_days: 14
  cors_allowed_origins: [https://admin.integration.test]
irc: { plaintext: true }
`)
	e := newEnv(t, func(c *config.Config) {
		c.AppConfig.ConfigFile = path
		c.AppConfig.ConfigPoll = 200 * time.Millisecond
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.app.StackConfig.Run(ctx)
	adminAT := e.adminToken("netadmin")

	// Effective values come from the file (env said registration open).
	r := e.api("GET", "/v1/admin/settings", nil, bearer(adminAT))
	e.expect(r, 200, "")
	if r.str("source") != "file" || r.str("registration") != "closed" || r.body["guest_access"] != false ||
		r.body["channel_expiry_days"] != float64(14) || r.body["require_email_verification"] != true {
		t.Fatalf("admin settings: %s", r.raw)
	}
	in := e.do(e.internal, "GET", "/internal/v1/settings", nil, header("X-Internal-Token", e.cfg.InternalConfig.APIToken))
	if in.str("registration") != "closed" || in.body["guest_access"] != false {
		t.Fatalf("internal settings: %s", in.raw)
	}
	if c := e.api("GET", "/v1/config", nil); c.str("registration") != "closed" || c.body["channel_expiry_days"] != float64(14) {
		t.Fatalf("/v1/config: %s", c.raw)
	}
	e.expect(e.api("POST", "/v1/register", map[string]string{"username": "early", "email": "early@example.com", "password": pw}), 403, "registration_closed")

	// Read-only through the API.
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"registration": "open"}, bearer(adminAT)), 409, "managed_by_config_file")

	// Status on the internal listener only.
	st := e.do(e.internal, "GET", "/internal/config/status", nil)
	e.expect(st, 200, "")
	if st.body["ok"] != true || st.body["enabled"] != true || st.body["present"] != true || st.str("loaded_at") == "" ||
		st.str("file_mtime") == "" || len(st.body["restart_required"].([]any)) != 0 {
		t.Fatalf("status: %s", st.raw)
	}
	e.expect(e.api("GET", "/internal/config/status", nil), 404, "")

	// CORS origins from the file.
	cors := func(origin string) string {
		return e.api("GET", "/v1/config", nil, header("Origin", origin)).header.Get("Access-Control-Allow-Origin")
	}
	if cors("https://admin.integration.test") != "https://admin.integration.test" || cors("https://app.integration.test") != "" {
		t.Fatal("CORS must follow the file")
	}

	// Live reload: open registration, rename the site, drop the CORS key
	// (back to the env value).
	writeConfig(t, path, `version: 1
network:
  name: Renamed Net
auth:
  registration: open
  guest_access: false
  channel_expiry_days: 14
`)
	eventually(t, "reload", func() bool {
		return e.api("GET", "/v1/config", nil).str("registration") == "open"
	})
	if cors("https://app.integration.test") != "https://app.integration.test" || cors("https://admin.integration.test") != "" {
		t.Fatal("CORS must reload live")
	}
	e.expect(e.api("POST", "/v1/register", map[string]string{"username": "late", "email": "late@example.com", "password": pw}), 201, "")
	if msg := e.mail.next(t); !strings.Contains(msg.Subject, "Renamed Net") {
		t.Fatalf("site name must reload live: %q", msg.Subject)
	}

	a := e.api("GET", "/v1/admin/audit?event=config_reloaded&limit=5", nil, bearer(adminAT))
	e.expect(a, 200, "")
	entries := a.list("entries")
	if len(entries) != 1 {
		t.Fatalf("audit: %s", a.raw)
	}
	meta := entries[0]["meta"].(map[string]any)
	var changed []string
	for _, k := range meta["changed"].([]any) {
		changed = append(changed, k.(string))
	}
	if meta["actor"] != "config file" || !slices.Equal(changed, []string{"auth.cors_allowed_origins", "auth.registration", "network.name"}) {
		t.Fatalf("audit meta: %v", meta)
	}

	// A broken edit keeps the last good config and is reported.
	writeConfig(t, path, "version: 1\nauth:\n  registration: closed\n  guest_access: perhaps\n")
	eventually(t, "error status", func() bool {
		return e.do(e.internal, "GET", "/internal/config/status", nil).body["ok"] == false
	})
	st = e.do(e.internal, "GET", "/internal/config/status", nil)
	if st.body["error_line"] != float64(4) || !strings.Contains(st.str("error"), "guest_access") {
		t.Fatalf("status: %s", st.raw)
	}
	if e.api("GET", "/v1/config", nil).str("registration") != "open" {
		t.Fatal("last good config must stay in use")
	}

	// File removed: back to env + database, PATCH works again.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	eventually(t, "database mode", func() bool {
		return e.api("GET", "/v1/admin/settings", nil, bearer(adminAT)).str("source") == "db"
	})
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"registration": "invite"}, bearer(adminAT)), 200, "")
}

func TestConfigStatusWithoutConfigFile(t *testing.T) {
	e := newEnv(t)
	st := e.do(e.internal, "GET", "/internal/config/status", nil)
	e.expect(st, 200, "")
	if st.body["enabled"] != false || st.body["ok"] != true {
		t.Fatalf("status: %s", st.raw)
	}
	if r := e.api("GET", "/v1/admin/settings", nil, bearer(e.adminToken("netadmin"))); r.str("source") != "db" {
		t.Fatalf("settings: %s", r.raw)
	}
}

// files_url in GET /v1/config: null until uploads are on, then
// FILES_PUBLIC_URL; files.enabled in the file switches it live.
func TestConfigFilesURL(t *testing.T) {
	// Env only, no URL: null.
	e := newEnv(t)
	if c := e.api("GET", "/v1/config", nil); c.body["files_url"] != nil {
		t.Fatalf("files_url without FILES_PUBLIC_URL: %s", c.raw)
	} else if _, ok := c.body["files_url"]; !ok {
		t.Fatalf("files_url must be present (null): %s", c.raw)
	}

	path := filepath.Join(t.TempDir(), "boson.yaml")
	writeConfig(t, path, "version: 1\n")
	e = newEnv(t, func(c *config.Config) {
		c.AppConfig.ConfigFile = path
		c.AppConfig.ConfigPoll = 200 * time.Millisecond
		c.FilesConfig.PublicURL = "https://files.integration.test/"
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.app.StackConfig.Run(ctx)
	filesURL := func() any { return e.api("GET", "/v1/config", nil).body["files_url"] }
	if u := filesURL(); u != nil {
		t.Fatalf("uploads are off by default, files_url = %v", u)
	}
	writeConfig(t, path, "version: 1\nfiles:\n  enabled: true\n  account: { quota: 5GB }\n")
	eventually(t, "files_url", func() bool { return filesURL() == "https://files.integration.test" })
	writeConfig(t, path, "version: 1\nfiles: { enabled: false }\n")
	eventually(t, "files_url null", func() bool { return filesURL() == nil })
}
