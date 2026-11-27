package integration

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
)

// Without a mail server (SMTP_HOST empty, ENV not development) auth sends
// nothing and says so: verification is off, no password reset by email,
// admins get links to copy.
func TestNoMailServer(t *testing.T) {
	e := newEnvNoMail(t, func(c *config.Config) { c.AccountConfig.SettingsCacheTTL = 0 })
	adminAT := e.adminToken("netadmin")

	cfg := e.api("GET", "/v1/config", nil)
	e.expect(cfg, 200, "")
	if cfg.body["require_email_verification"] != false || cfg.body["email"].(map[string]any)["configured"] != false {
		t.Fatalf("/v1/config: %s", cfg.raw)
	}
	if acc := cfg.body["accounts"].(map[string]any); acc["backend"] != "local" || acc["password_reset"] != false || acc["signup"] != true {
		t.Fatalf("accounts: %v", acc)
	}
	// The admin sees the configured value and what is enforced.
	st := e.api("GET", "/v1/admin/settings", nil, bearer(adminAT))
	e.expect(st, 200, "")
	if st.body["require_email_verification"] != true || st.body["require_email_verification_effective"] != false || st.body["email_configured"] != false {
		t.Fatalf("admin settings: %s", st.raw)
	}

	// Sign-up: nothing to verify, sign in right away.
	reg := e.api("POST", "/v1/register", map[string]string{"username": "newbie", "email": "newbie@example.com", "password": pw})
	e.expect(reg, 201, "")
	if reg.body["email_verification_sent"] != false || reg.body["email_verification_required"] != false {
		t.Fatalf("register: %s", reg.raw)
	}
	e.expect(e.login("newbie", pw), 200, "")
	var tokens int
	if err := e.sqlDB().QueryRow(`SELECT count(*) FROM email_tokens WHERE user_id = $1`, reg.str("user", "id")).Scan(&tokens); err != nil || tokens != 0 {
		t.Fatalf("verification tokens: %d %v", tokens, err)
	}

	// Nothing pretends to send.
	e.expect(e.api("POST", "/v1/password/forgot", map[string]string{"email": "newbie@example.com"}), 409, "email_not_configured")
	e.expect(e.api("POST", "/v1/email/resend", map[string]string{"email": "newbie@example.com"}), 409, "email_not_configured")
	uid := reg.str("user", "id")
	e.expect(e.api("POST", "/v1/admin/users/"+uid+"/verification", nil, bearer(adminAT)), 409, "email_not_configured")
	e.expect(e.do(e.internal, "POST", "/internal/email/test", map[string]any{"template": "verification", "to": "me@example.com"}, bearer(adminAT)),
		409, "email_not_configured")

	// Password reset: the admin gets the link to hand over, and it works.
	r := e.api("POST", "/v1/admin/users/"+uid+"/password-reset", nil, bearer(adminAT))
	e.expect(r, 200, "")
	link := r.str("link")
	if r.body["email_sent"] != false || !strings.HasPrefix(link, "https://app.integration.test/") {
		t.Fatalf("password-reset: %s", r.raw)
	}
	e.expect(e.api("POST", "/v1/password/reset", map[string]string{"token": tokenFromLink(t, link), "new_password": "a-new-password-123"}), 200, "")
	e.expect(e.login("newbie", "a-new-password-123"), 200, "")
	a := e.api("GET", "/v1/admin/audit?event=admin_password_reset_sent", nil, bearer(adminAT))
	if entries := a.list("entries"); len(entries) != 1 || entries[0]["meta"].(map[string]any)["delivery"] != "link" {
		t.Fatalf("audit: %s", a.raw)
	}

	// Create user + "invite email": the setup link instead (no email needed).
	cu := e.api("POST", "/v1/admin/users", map[string]any{"username": "invitee", "email": "invitee@example.com", "send_invite_email": true}, bearer(adminAT))
	e.expect(cu, 201, "")
	setup := cu.str("setup_link")
	if cu.body["invite_email_sent"] != false || setup == "" {
		t.Fatalf("create user: %s", cu.raw)
	}
	e.expect(e.api("POST", "/v1/password/reset", map[string]string{"token": tokenFromLink(t, setup), "new_password": "invitee-password-1"}), 200, "")
	e.expect(e.login("invitee", "invitee-password-1"), 200, "")
	noEmail := e.api("POST", "/v1/admin/users", map[string]any{"username": "noemail"}, bearer(adminAT))
	e.expect(noEmail, 201, "")
	r = e.api("POST", "/v1/admin/users/"+noEmail.str("user", "id")+"/password-reset", nil, bearer(adminAT))
	e.expect(r, 200, "")
	if r.str("link") == "" {
		t.Fatalf("no-email user reset: %s", r.raw)
	}
}

// A mail server added through the config file turns email (and with it
// verification and password reset) back on live, and removing it turns
// them off again.
func TestNoMailServerLiveConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boson.yaml")
	writeConfig(t, path, "version: 1\nauth:\n  require_email_verification: true\n")
	e := newEnvNoMail(t, func(c *config.Config) {
		c.AppConfig.ConfigFile = path
		c.AppConfig.ConfigPoll = 200 * time.Millisecond
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.app.StackConfig.Run(ctx)

	configured := func() (bool, bool, bool) {
		r := e.api("GET", "/v1/config", nil)
		return r.body["email"].(map[string]any)["configured"] == true, r.body["require_email_verification"] == true,
			r.body["accounts"].(map[string]any)["password_reset"] == true
	}
	if c, v, p := configured(); c || v || p {
		t.Fatalf("no mail server: configured=%v verification=%v reset=%v", c, v, p)
	}
	reg := e.api("POST", "/v1/register", map[string]string{"username": "early", "email": "early@example.com", "password": pw})
	e.expect(reg, 201, "")
	e.expect(e.login("early", pw), 200, "")

	// No connection is made until something is sent.
	writeConfig(t, path, "version: 1\nauth:\n  require_email_verification: true\n  smtp: { host: smtp.invalid, from: \"Boson <hi@example.com>\" }\n")
	eventually(t, "mail server configured", func() bool { c, v, p := configured(); return c && v && p })
	// Now verification applies again, to the earlier account too.
	e.expect(e.login("early", pw), 403, "email_not_verified")

	writeConfig(t, path, "version: 1\nauth:\n  require_email_verification: true\n")
	eventually(t, "mail server removed", func() bool { c, _, _ := configured(); return !c })
	e.expect(e.login("early", pw), 200, "")
}

// With the NickServ backend the services verify emails, so the setting
// stays in force without a mail server.
func TestNoMailServerNickServ(t *testing.T) {
	f := newFakeServicesRPC(t, "")
	e := newEnvNoMail(t, func(c *config.Config) {
		c.AccountsConfig.Backend = config.AccountBackendNickServ
		c.NickServConfig = config.NickServConfig{
			Strategy: config.StrategyAthemeJSONRPC, RPCURL: f.srv.URL,
			Timeout: 5 * time.Second, MaxConcurrent: 4, ServiceNick: "NickServ",
			Registration: true, LinkExisting: config.LinkExistingUnclaimed, StoreSession: true,
			RateAccountBurst: 1000, RateAccountPerMinute: 1000, RateIPBurst: 1000, RateIPPerMinute: 1000,
			LockoutThreshold: 3, LockoutIPThreshold: 100, LockoutWindow: 15 * time.Minute, LockoutDuration: 15 * time.Minute,
		}
	})
	cfg := e.api("GET", "/v1/config", nil)
	if cfg.body["require_email_verification"] != true || cfg.body["email"].(map[string]any)["configured"] != false {
		t.Fatalf("/v1/config: %s", cfg.raw)
	}
	r := e.api("POST", "/v1/register", map[string]string{"username": "Gina", "email": "gina@example.org", "password": nsPassword})
	e.expect(r, 201, "")
	if r.str("verification") != "nickserv_code" || r.body["email_verification_required"] != true {
		t.Fatalf("register = %s", r.raw)
	}
	e.expect(e.login("gina", nsPassword), 403, "email_not_verified")
}

// auth.nickserv.registration / signup_message switch Boson sign-up live.
func TestNickServSignupFromConfigFile(t *testing.T) {
	f := newFakeServicesRPC(t, "")
	path := filepath.Join(t.TempDir(), "boson.yaml")
	writeConfig(t, path, "version: 1\nauth:\n  nickserv:\n    registration: false\n    signup_message: Register on IRC first, then sign in here.\n")
	e := nickServEnv(t, config.StrategyAthemeJSONRPC, f)
	e.cfg.AppConfig.ConfigFile = path
	e.cfg.AppConfig.ConfigPoll = 200 * time.Millisecond
	e.restart()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.app.StackConfig.Run(ctx)

	accounts := func() map[string]any { return e.api("GET", "/v1/config", nil).body["accounts"].(map[string]any) }
	if acc := accounts(); acc["signup"] != false || acc["signup_message"] != "Register on IRC first, then sign in here." {
		t.Fatalf("accounts = %v", acc)
	}
	r := e.api("POST", "/v1/register", map[string]string{"username": "Gina", "email": "gina@example.org", "password": nsPassword})
	e.expect(r, 403, "registration_unavailable")
	if r.str("message") != "Register on IRC first, then sign in here." {
		t.Fatalf("message %q", r.str("message"))
	}

	writeConfig(t, path, "version: 1\nauth:\n  nickserv: { registration: true }\n")
	eventually(t, "sign-up on", func() bool { acc := accounts(); return acc["signup"] == true && acc["signup_message"] == nil })
	e.expect(e.api("POST", "/v1/register", map[string]string{"username": "Gina", "email": "gina@example.org", "password": nsPassword}), 201, "")

	// Off without a message: the default points at IRC.
	writeConfig(t, path, "version: 1\nauth:\n  nickserv: { registration: false }\n")
	eventually(t, "sign-up off", func() bool { return accounts()["signup"] == false })
	if msg, _ := accounts()["signup_message"].(string); !strings.Contains(msg, "/msg NickServ REGISTER") {
		t.Fatalf("default message %q", msg)
	}
	// A pending registration can still be confirmed.
	e.expect(e.api("POST", "/v1/register/confirm", map[string]string{"username": "gina", "password": nsPassword, "code": "key-gina"}), 200, "")
}
