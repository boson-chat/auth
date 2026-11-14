package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
)

func TestNetworkSettings(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.AccountConfig.ChannelCreation = config.ChannelCreationRegistered
		c.AccountConfig.VoiceChannelCreation = config.VoiceChannelCreationFounders
		c.AccountConfig.SettingsCacheTTL = 0
	})
	adminAT := e.adminToken("netadmin")
	e.registerVerified("norm", "norm@example.com")
	userAT := e.login("norm", pw).str("access_token")

	// Defaults come from the environment; never updated yet.
	r := e.api("GET", "/v1/admin/settings", nil, bearer(adminAT))
	e.expect(r, 200, "")
	if r.str("registration") != "open" || r.body["require_email_verification"] != true ||
		r.str("channel_creation") != "registered" || r.str("voice_channel_creation") != "founders" ||
		r.body["updated_at"] != nil || r.body["updated_by"] != nil {
		t.Fatalf("defaults: %s", r.raw)
	}
	e.expect(e.api("GET", "/v1/admin/settings", nil, bearer(userAT)), 403, "forbidden")
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"registration": "closed"}, bearer(userAT)), 403, "forbidden")
	e.expect(e.api("GET", "/v1/admin/settings", nil), 401, "")

	// Invalid values are rejected and change nothing.
	for _, bad := range []map[string]any{
		{"registration": "maybe"}, {"channel_creation": "founders"}, {"voice_channel_creation": "everyone"}, {},
	} {
		e.expect(e.api("PATCH", "/v1/admin/settings", bad, bearer(adminAT)), 400, "invalid_request")
	}
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"require_email_verification": "no"}, bearer(adminAT)), 400, "")

	// Partial update.
	r = e.api("PATCH", "/v1/admin/settings", map[string]any{"registration": "closed", "voice_channel_creation": "admins"}, bearer(adminAT))
	e.expect(r, 200, "")
	adminID := e.api("GET", "/v1/me", nil, bearer(adminAT)).str("user", "id")
	if r.str("registration") != "closed" || r.str("voice_channel_creation") != "admins" || r.str("channel_creation") != "registered" ||
		r.str("updated_by") != adminID || r.str("updated_at") == "" {
		t.Fatalf("patched: %s", r.raw)
	}

	// Live: registration closes without a restart.
	e.expect(e.api("POST", "/v1/register", map[string]string{"username": "late", "email": "late@example.com", "password": pw}), 403, "registration_closed")
	cfg := e.api("GET", "/v1/config", nil)
	if cfg.str("registration") != "closed" || cfg.str("voice_channel_creation") != "admins" || cfg.str("channel_creation") != "registered" {
		t.Fatalf("/v1/config: %s", cfg.raw)
	}

	// Internal API serves the same object.
	e.expect(e.do(e.internal, "GET", "/internal/v1/settings", nil), 401, "")
	in := e.do(e.internal, "GET", "/internal/v1/settings", nil, header("X-Internal-Token", e.cfg.InternalConfig.APIToken))
	e.expect(in, 200, "")
	if in.str("registration") != "closed" || in.str("voice_channel_creation") != "admins" || in.str("updated_by") != adminID {
		t.Fatalf("internal settings: %s", in.raw)
	}
	e.expect(e.api("GET", "/internal/v1/settings", nil, header("X-Internal-Token", e.cfg.InternalConfig.APIToken)), 404, "")

	// Invite mode needs a code.
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"registration": "invite"}, bearer(adminAT)), 200, "")
	e.expect(e.api("POST", "/v1/register", map[string]string{"username": "late", "email": "late@example.com", "password": pw}), 403, "invite_required")

	// Turning verification off lets unverified accounts log in (and SASL).
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"registration": "open", "require_email_verification": false}, bearer(adminAT)), 200, "")
	reg := e.api("POST", "/v1/register", map[string]string{"username": "late", "email": "late@example.com", "password": pw})
	e.expect(reg, 201, "")
	if reg.body["email_verification_required"] != false {
		t.Fatalf("register: %s", reg.raw)
	}
	e.mail.next(t)
	e.expect(e.login("late", pw), 200, "")
	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"require_email_verification": true}, bearer(adminAT)), 200, "")
	e.expect(e.login("late", pw), 403, "email_not_verified")

	// Audit: old/new of the changed fields only.
	a := e.api("GET", "/v1/admin/audit?event=settings_updated&limit=1", nil, bearer(adminAT))
	e.expect(a, 200, "")
	entries := a.list("entries")
	if len(entries) != 1 || entries[0]["actor_username"] != "netadmin" {
		t.Fatalf("audit: %s", a.raw)
	}
	meta := entries[0]["meta"].(map[string]any)
	if fmt.Sprint(meta["old"]) != "map[require_email_verification:false]" || fmt.Sprint(meta["new"]) != "map[require_email_verification:true]" {
		t.Fatalf("audit meta: %v", meta)
	}
}

func TestChannelLifecycleSettings(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.AccountConfig.ChannelAutoRegister = true
		c.AccountConfig.ChannelExpiryDays = 0
		c.AccountConfig.SettingsCacheTTL = 0
	})
	adminAT := e.adminToken("netadmin")
	tok := header("X-Internal-Token", e.cfg.InternalConfig.APIToken)
	check := func(name string, r resp, auto bool, days float64) {
		t.Helper()
		e.expect(r, 200, "")
		if r.body["channel_auto_register"] != auto || r.body["channel_expiry_days"] != days {
			t.Fatalf("%s: %s", name, r.raw)
		}
	}
	all := func(auto bool, days float64) {
		t.Helper()
		check("admin", e.api("GET", "/v1/admin/settings", nil, bearer(adminAT)), auto, days)
		check("internal", e.do(e.internal, "GET", "/internal/v1/settings", nil, tok), auto, days)
		check("config", e.api("GET", "/v1/config", nil), auto, days)
	}
	all(true, 0)

	for bad, msg := range map[string]string{
		`{"channel_expiry_days": -1}`:     "channel_expiry_days must be between 0 and 3650 (0 = never expire)",
		`{"channel_expiry_days": 3651}`:   "channel_expiry_days must be between 0 and 3650 (0 = never expire)",
		`{"channel_expiry_days": 1.5}`:    "channel_expiry_days must be an integer",
		`{"channel_expiry_days": "30"}`:   "channel_expiry_days must be an integer",
		`{"channel_auto_register": "no"}`: "channel_auto_register must be a boolean",
		`{"channel_auto_register": 0}`:    "channel_auto_register must be a boolean",
		`{"channel_auto_register": null}`: "nothing to update",
	} {
		r := e.api("PATCH", "/v1/admin/settings", json.RawMessage(bad), bearer(adminAT))
		e.expect(r, 400, "invalid_request")
		if r.str("message") != msg {
			t.Errorf("%s: message %q, want %q", bad, r.str("message"), msg)
		}
	}
	all(true, 0)

	r := e.api("PATCH", "/v1/admin/settings", map[string]any{"channel_auto_register": false, "channel_expiry_days": 90}, bearer(adminAT))
	check("patch", r, false, 90)
	if r.str("channel_creation") != "registered" {
		t.Fatalf("partial patch touched other fields: %s", r.raw)
	}
	all(false, 90)
	check("upper bound", e.api("PATCH", "/v1/admin/settings", map[string]any{"channel_expiry_days": 3650}, bearer(adminAT)), false, 3650)
	check("never", e.api("PATCH", "/v1/admin/settings", map[string]any{"channel_expiry_days": 0}, bearer(adminAT)), false, 0)

	a := e.api("GET", "/v1/admin/audit?event=settings_updated&limit=3", nil, bearer(adminAT))
	e.expect(a, 200, "")
	entries := a.list("entries")
	if len(entries) != 3 {
		t.Fatalf("audit: %s", a.raw)
	}
	first := entries[2]["meta"].(map[string]any)
	if fmt.Sprint(first["old"]) != "map[channel_auto_register:true channel_expiry_days:0]" ||
		fmt.Sprint(first["new"]) != "map[channel_auto_register:false channel_expiry_days:90]" {
		t.Fatalf("audit meta: %v", first)
	}
	last := entries[0]["meta"].(map[string]any)
	if fmt.Sprint(last["old"]) != "map[channel_expiry_days:3650]" || fmt.Sprint(last["new"]) != "map[channel_expiry_days:0]" {
		t.Fatalf("audit meta: %v", last)
	}
}

func TestSettingsCacheIsShortLived(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.AccountConfig.SettingsCacheTTL = 200 * time.Millisecond })
	if e.api("GET", "/v1/config", nil).str("registration") != "open" {
		t.Fatal("default")
	}
	// Another replica writes directly to the database.
	if err := e.app.DB.DB.Exec(`UPDATE network_settings SET registration = 'closed'`).Error; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for e.api("GET", "/v1/config", nil).str("registration") != "closed" {
		if time.Now().After(deadline) {
			t.Fatal("cached settings never refreshed")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestVersionEndpoint(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.AppConfig.Version = "9.9.9-test" })
	for _, srv := range []string{"public", "internal"} {
		s := e.public
		if srv == "internal" {
			s = e.internal
		}
		res, err := e.client.Get(s.URL + "/version")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || string(b) != "9.9.9-test\n" || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/plain") {
			t.Fatalf("%s /version: %d %q %s", srv, res.StatusCode, b, res.Header.Get("Content-Type"))
		}
	}
}

func TestAdminCreateUser(t *testing.T) {
	e := newEnv(t)
	adminAT := e.ownerToken("creator") // only an Owner may hand out Admin

	// With a password: email verified, can log in straight away.
	r := e.api("POST", "/v1/admin/users", map[string]any{"username": "Made", "email": "made@example.com", "role": "user", "password": pw}, bearer(adminAT))
	e.expect(r, 201, "")
	if r.body["user"].(map[string]any)["email_verified"] != true || r.body["invite_email_sent"] != false {
		t.Fatalf("create: %s", r.raw)
	}
	e.expect(e.login("made", pw), 200, "")
	e.mail.none(t, 100*time.Millisecond)

	// Conflicts and validation.
	e.expect(e.api("POST", "/v1/admin/users", map[string]any{"username": "made", "email": "x@example.com"}, bearer(adminAT)), 409, "username_taken")
	e.expect(e.api("POST", "/v1/admin/users", map[string]any{"username": "other", "email": "MADE@example.com"}, bearer(adminAT)), 409, "email_taken")
	e.expect(e.api("POST", "/v1/admin/users", map[string]any{"username": "other", "email": "o@example.com", "role": "root"}, bearer(adminAT)), 400, "invalid_request")
	e.expect(e.api("POST", "/v1/admin/users", map[string]any{"username": "other", "email": "o@example.com", "password": "short"}, bearer(adminAT)), 400, "weak_password")
	e.expect(e.api("POST", "/v1/admin/users", map[string]any{"username": "other", "email": "o@example.com", "password": pw, "send_invite_email": true}, bearer(adminAT)), 400, "invalid_request")
	e.expect(e.api("POST", "/v1/admin/users", map[string]any{"username": "other", "send_invite_email": true}, bearer(adminAT)), 400, "invalid_request")
	e.expect(e.api("POST", "/v1/admin/users", map[string]any{"username": "other", "email": "o@example.com"}, bearer(e.login("made", pw).str("access_token"))), 403, "forbidden")

	// An Admin can create users but not other Admins (role hierarchy).
	plainAdmin := e.adminToken("plainadmin")
	e.expect(e.api("POST", "/v1/admin/users", map[string]any{"username": "other", "email": "o@example.com", "role": "admin"}, bearer(plainAdmin)), 403, "role_hierarchy")
	e.expect(e.api("POST", "/v1/admin/users", map[string]any{"username": "other", "email": "o@example.com"}, bearer(plainAdmin)), 201, "")

	// With an invite email: a "choose your password" link on the reset page.
	r = e.api("POST", "/v1/admin/users", map[string]any{"username": "invited", "email": "invited@example.com", "role": "admin", "send_invite_email": true}, bearer(adminAT))
	e.expect(r, 201, "")
	if r.body["invite_email_sent"] != true || r.str("user", "role") != "admin" {
		t.Fatalf("create with invite: %s", r.raw)
	}
	invitedID := r.str("user", "id")
	msg := e.mail.next(t)
	if msg.To != "invited@example.com" || !strings.HasPrefix(msg.Link, "https://app.integration.test/reset-password#token=") || !strings.Contains(msg.Text, "choose your password") {
		t.Fatalf("setup email: %s %s\n%s", msg.To, msg.Link, msg.Text)
	}
	e.expect(e.login("invited", pw), 401, "invalid_credentials") // no password yet
	e.expect(e.api("POST", "/v1/password/reset", map[string]string{"token": tokenFromLink(t, msg.Link), "new_password": pw}), 200, "")
	e.expect(e.login("invited", pw), 200, "")

	// No email, no password: an SSO-only style account.
	r = e.api("POST", "/v1/admin/users", map[string]any{"username": "bare"}, bearer(adminAT))
	e.expect(r, 201, "")
	if r.body["user"].(map[string]any)["email"] != nil {
		t.Fatalf("bare: %s", r.raw)
	}

	a := e.api("GET", "/v1/admin/audit?event=admin_user_created&target="+invitedID, nil, bearer(adminAT))
	e.expect(a, 200, "")
	if es := a.list("entries"); len(es) != 1 || es[0]["actor_username"] != "creator" || es[0]["target_username"] != "invited" || es[0]["target_user_id"] != invitedID {
		t.Fatalf("audit: %s", a.raw)
	}
}

func TestAdminSendResetAndVerification(t *testing.T) {
	e := newEnv(t)
	adminAT := e.adminToken("helper")
	uid := e.registerVerified("forgetful", "forgetful@example.com")

	e.expect(e.api("POST", "/v1/admin/users/"+uid+"/password-reset", nil, bearer(adminAT)), 202, "")
	msg := e.mail.next(t)
	if msg.To != "forgetful@example.com" || !strings.Contains(msg.Link, "/reset-password#token=") {
		t.Fatalf("reset email: %s %s", msg.To, msg.Link)
	}
	e.expect(e.api("POST", "/v1/password/reset", map[string]string{"token": tokenFromLink(t, msg.Link), "new_password": "a brand new password"}), 200, "")
	e.expect(e.login("forgetful", "a brand new password"), 200, "")

	// Already verified.
	e.expect(e.api("POST", "/v1/admin/users/"+uid+"/verification", nil, bearer(adminAT)), 409, "already_verified")

	// Unverified user gets a new link.
	e.expect(e.api("POST", "/v1/register", map[string]string{"username": "slow", "email": "slow@example.com", "password": pw}), 201, "")
	e.mail.next(t)
	slow := e.api("GET", "/v1/admin/users?q=slow", nil, bearer(adminAT)).list("users")[0]["id"].(string)
	e.expect(e.api("POST", "/v1/admin/users/"+slow+"/verification", nil, bearer(adminAT)), 202, "")
	msg = e.mail.next(t)
	if msg.To != "slow@example.com" || !strings.Contains(msg.Link, "/verify-email#token=") {
		t.Fatalf("verify email: %s %s", msg.To, msg.Link)
	}
	e.expect(e.api("POST", "/v1/email/verify", map[string]string{"token": tokenFromLink(t, msg.Link)}), 200, "")

	// Errors.
	e.expect(e.api("POST", "/v1/admin/users/usr_nope/password-reset", nil, bearer(adminAT)), 404, "not_found")
	e.expect(e.api("POST", "/v1/admin/users/usr_nope/verification", nil, bearer(adminAT)), 404, "not_found")
	bare := e.api("POST", "/v1/admin/users", map[string]any{"username": "noemail"}, bearer(adminAT)).str("user", "id")
	e.expect(e.api("POST", "/v1/admin/users/"+bare+"/password-reset", nil, bearer(adminAT)), 400, "no_email")
	e.expect(e.api("POST", "/v1/admin/users/"+uid+"/disable", nil, bearer(adminAT)), 200, "")
	e.expect(e.api("POST", "/v1/admin/users/"+uid+"/password-reset", nil, bearer(adminAT)), 409, "account_disabled")
	e.expect(e.api("POST", "/v1/admin/users/"+uid+"/password-reset", nil, bearer(e.login("slow", pw).str("access_token"))), 403, "forbidden")

	a := e.api("GET", "/v1/admin/audit?event=admin_password_reset_sent,admin_verification_sent", nil, bearer(adminAT))
	if es := a.list("entries"); len(es) != 2 || es[0]["event"] != "admin_verification_sent" || es[0]["target_username"] != "slow" || es[1]["target_username"] != "forgetful" {
		t.Fatalf("audit: %s", a.raw)
	}
}

func TestAdminAuditFiltersAndPagination(t *testing.T) {
	e := newEnv(t)
	adminAT := e.adminToken("auditor")
	uid := e.registerVerified("subject", "subject@example.com")
	for range 5 {
		e.expect(e.login("subject", pw), 200, "")
	}
	e.expect(e.api("POST", "/v1/admin/users/"+uid+"/disable", nil, bearer(adminAT)), 200, "")

	// Keyset pagination over everything the subject did (5 logins), 2 per page.
	var seen []string
	cursor := ""
	for page := 0; ; page++ {
		q := url.Values{"actor": {"SUBJECT"}, "event": {"login"}, "limit": {"2"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		r := e.api("GET", "/v1/admin/audit?"+q.Encode(), nil, bearer(adminAT))
		e.expect(r, 200, "")
		for _, en := range r.list("entries") {
			if en["actor_username"] != "subject" || en["actor_user_id"] != uid || en["user_id"] != uid || en["event"] != "login" {
				t.Fatalf("entry: %v", en)
			}
			seen = append(seen, en["id"].(string))
		}
		next, _ := r.body["next_cursor"].(string)
		if next == "" {
			if _, present := r.body["next_cursor"]; !present {
				t.Fatal("next_cursor must be present (null on the last page)")
			}
			break
		}
		if page > 5 {
			t.Fatal("pagination never ended")
		}
		cursor = next
	}
	if len(seen) != 5 {
		t.Fatalf("paged %d logins, want 5: %v", len(seen), seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] == seen[i-1] {
			t.Fatal("duplicate across pages")
		}
	}

	// target= finds the admin action; user_id= finds both sides.
	r := e.api("GET", "/v1/admin/audit?target="+uid, nil, bearer(adminAT))
	if es := r.list("entries"); len(es) != 1 || es[0]["event"] != "admin_user_disabled" || es[0]["actor_username"] != "auditor" || es[0]["target_username"] != "subject" {
		t.Fatalf("target filter: %s", r.raw)
	}
	r = e.api("GET", "/v1/admin/audit?limit=200&user_id="+uid, nil, bearer(adminAT))
	if es := r.list("entries"); len(es) < 7 { // register, verify, 5 logins, disable
		t.Fatalf("user_id filter: %d entries", len(es))
	}

	// Time window.
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if es := e.api("GET", "/v1/admin/audit?since="+future, nil, bearer(adminAT)).list("entries"); len(es) != 0 {
		t.Fatalf("since in the future: %d", len(es))
	}
	if es := e.api("GET", "/v1/admin/audit?until="+future+"&event=admin_user_disabled", nil, bearer(adminAT)).list("entries"); len(es) != 1 {
		t.Fatalf("until: %d", len(es))
	}

	// Unknown user filter → empty, bad input → 400.
	if es := e.api("GET", "/v1/admin/audit?actor=nobody", nil, bearer(adminAT)).list("entries"); len(es) != 0 {
		t.Fatal("unknown actor matched")
	}
	e.expect(e.api("GET", "/v1/admin/audit?cursor=garbage", nil, bearer(adminAT)), 400, "invalid_request")
	e.expect(e.api("GET", "/v1/admin/audit?since=yesterday", nil, bearer(adminAT)), 400, "invalid_request")
}

func TestGuestAccessSetting(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.AccountConfig.GuestAccess = true
		c.AccountConfig.SettingsCacheTTL = 0
	})
	adminAT := e.adminToken("netadmin")
	tok := header("X-Internal-Token", e.cfg.InternalConfig.APIToken)
	all := func(want bool) {
		t.Helper()
		for name, r := range map[string]resp{
			"admin":    e.api("GET", "/v1/admin/settings", nil, bearer(adminAT)),
			"internal": e.do(e.internal, "GET", "/internal/v1/settings", nil, tok),
			"config":   e.api("GET", "/v1/config", nil),
		} {
			e.expect(r, 200, "")
			if r.body["guest_access"] != want {
				t.Fatalf("%s: guest_access want %v: %s", name, want, r.raw)
			}
		}
	}
	all(true)

	for bad, msg := range map[string]string{
		`{"guest_access": "no"}`: "guest_access must be a boolean",
		`{"guest_access": 1}`:    "guest_access must be a boolean",
		`{"guest_access": null}`: "nothing to update",
	} {
		r := e.api("PATCH", "/v1/admin/settings", json.RawMessage(bad), bearer(adminAT))
		e.expect(r, 400, "invalid_request")
		if r.str("message") != msg {
			t.Errorf("%s: message %q, want %q", bad, r.str("message"), msg)
		}
	}
	all(true)

	r := e.api("PATCH", "/v1/admin/settings", map[string]any{"guest_access": false}, bearer(adminAT))
	e.expect(r, 200, "")
	if r.body["guest_access"] != false || r.body["channel_auto_register"] != true || r.str("registration") != "open" {
		t.Fatalf("patch: %s", r.raw)
	}
	all(false)

	a := e.api("GET", "/v1/admin/audit?event=settings_updated&limit=1", nil, bearer(adminAT))
	e.expect(a, 200, "")
	entries := a.list("entries")
	if len(entries) != 1 {
		t.Fatalf("audit: %s", a.raw)
	}
	meta := entries[0]["meta"].(map[string]any)
	if fmt.Sprint(meta["old"]) != "map[guest_access:true]" || fmt.Sprint(meta["new"]) != "map[guest_access:false]" {
		t.Fatalf("audit meta: %v", meta)
	}

	e.expect(e.api("PATCH", "/v1/admin/settings", map[string]any{"guest_access": true}, bearer(adminAT)), 200, "")
	all(true)
}
