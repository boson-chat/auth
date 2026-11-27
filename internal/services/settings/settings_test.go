package settings

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	auditrepo "github.com/boson-chat/auth/internal/db/repositories/audit"
	settingsrepo "github.com/boson-chat/auth/internal/db/repositories/settings"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/rs/zerolog"
)

type memRepo struct {
	mu    sync.Mutex
	row   settingsrepo.Row
	reads int
}

func (m *memRepo) Get(context.Context) (*settingsrepo.Row, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	r := m.row
	return &r, nil
}
func (m *memRepo) GetForUpdate(ctx context.Context) (*settingsrepo.Row, error) { return m.Get(ctx) }
func (m *memRepo) Save(_ context.Context, r *settingsrepo.Row) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.row = *r
	return nil
}

type auditSpy struct {
	events []string
	metas  []map[string]any
}

func (a *auditSpy) Record(_ context.Context, _, event string, meta map[string]any) {
	a.events = append(a.events, event)
	a.metas = append(a.metas, meta)
}
func (a *auditSpy) RecordTarget(ctx context.Context, actor, _, event string, meta map[string]any) {
	a.Record(ctx, actor, event, meta)
}
func (a *auditSpy) List(context.Context, auditrepo.Filter) ([]*auditrepo.EntryView, error) {
	return nil, nil
}

func ptr[T any](v T) *T { return &v }

func newSvc(ttl time.Duration) (*SettingsService, *memRepo, *auditSpy, *time.Time) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repo, spy := &memRepo{}, &auditSpy{}
	defaults := config.AccountConfig{
		Registration: "invite", RequireEmailVerification: true,
		ChannelCreation: "registered", VoiceChannelCreation: "founders", ChannelAutoRegister: true, ChannelExpiryDays: 0, GuestAccess: true,
		SettingsCacheTTL: ttl,
	}
	s := NewSettingsService(repo, db.NoTx{}, spy, defaults, func() time.Time { return now }).(*SettingsService)
	return s, repo, spy, &now
}

func TestDefaultsThenOverrides(t *testing.T) {
	s, _, spy, _ := newSvc(0)
	got, err := s.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.Registration != "invite" || !got.RequireEmailVerification || got.ChannelCreation != "registered" ||
		got.VoiceChannelCreation != "founders" || got.UpdatedAt != nil || got.UpdatedBy != nil {
		t.Fatalf("defaults: %+v", got)
	}
	got, err = s.Update(t.Context(), "usr_admin", Patch{RequireEmailVerification: ptr(false), ChannelCreation: ptr("admins")})
	if err != nil {
		t.Fatal(err)
	}
	if got.Registration != "invite" || got.RequireEmailVerification || got.ChannelCreation != "admins" ||
		got.UpdatedBy == nil || *got.UpdatedBy != "usr_admin" || got.UpdatedAt == nil {
		t.Fatalf("after patch: %+v", got)
	}
	if len(spy.events) != 1 || spy.events[0] != "settings_updated" {
		t.Fatalf("audit: %v", spy.events)
	}
	oldV, newV := spy.metas[0]["old"].(map[string]any), spy.metas[0]["new"].(map[string]any)
	if len(oldV) != 2 || oldV["require_email_verification"] != true || newV["require_email_verification"] != false ||
		oldV["channel_creation"] != "registered" || newV["channel_creation"] != "admins" {
		t.Fatalf("audit diff: old=%v new=%v", oldV, newV)
	}
}

func TestInvalidPatch(t *testing.T) {
	s, repo, spy, _ := newSvc(0)
	for _, p := range []Patch{
		{},
		{Registration: ptr("sometimes")},
		{ChannelCreation: ptr("founders")},
		{VoiceChannelCreation: ptr("")},
		{ChannelExpiryDays: ptr(-1)},
		{ChannelExpiryDays: ptr(3651)},
		{ChannelAutoRegister: ptr(false), ChannelExpiryDays: ptr(1 << 40)},
	} {
		_, err := s.Update(t.Context(), "usr_a", p)
		if e, ok := apperr.As(err); !ok || e.Status != 400 {
			t.Fatalf("%+v: err = %v", p, err)
		}
	}
	if repo.row.UpdatedAt != nil || len(spy.events) != 0 {
		t.Fatal("invalid patch was stored or audited")
	}
}

func TestChannelLifecycleSettings(t *testing.T) {
	s, repo, spy, _ := newSvc(0)
	got, err := s.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !got.ChannelAutoRegister || got.ChannelExpiryDays != 0 {
		t.Fatalf("defaults: %+v", got)
	}
	got, err = s.Update(t.Context(), "usr_admin", Patch{ChannelAutoRegister: ptr(false), ChannelExpiryDays: ptr(90)})
	if err != nil {
		t.Fatal(err)
	}
	if got.ChannelAutoRegister || got.ChannelExpiryDays != 90 || got.ChannelCreation != "registered" {
		t.Fatalf("after patch: %+v", got)
	}
	if repo.row.ChannelAutoRegister == nil || *repo.row.ChannelAutoRegister || repo.row.ChannelExpiryDays == nil ||
		*repo.row.ChannelExpiryDays != 90 || repo.row.ChannelCreation != nil {
		t.Fatalf("stored: %+v", repo.row)
	}
	oldV, newV := spy.metas[0]["old"].(map[string]any), spy.metas[0]["new"].(map[string]any)
	if len(oldV) != 2 || oldV["channel_auto_register"] != true || newV["channel_auto_register"] != false ||
		oldV["channel_expiry_days"] != 0 || newV["channel_expiry_days"] != 90 {
		t.Fatalf("audit diff: old=%v new=%v", oldV, newV)
	}
	// Both bounds are allowed; only the changed field is audited.
	for _, n := range []int{3650, 0} {
		if got, err = s.Update(t.Context(), "usr_admin", Patch{ChannelExpiryDays: ptr(n)}); err != nil || got.ChannelExpiryDays != n {
			t.Fatalf("expiry %d: %+v %v", n, got, err)
		}
	}
	if newV := spy.metas[2]["new"].(map[string]any); len(newV) != 1 || newV["channel_expiry_days"] != 0 {
		t.Fatalf("audit diff: %v", newV)
	}
}

func TestCacheTTL(t *testing.T) {
	s, repo, _, now := newSvc(5 * time.Second)
	for range 3 {
		if _, err := s.Get(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if repo.reads != 1 {
		t.Fatalf("reads = %d, want 1 (cached)", repo.reads)
	}
	// A write by another replica shows up once the TTL has passed.
	repo.row.Registration = ptr("closed")
	if got, _ := s.Get(t.Context()); got.Registration != "invite" {
		t.Fatal("expected cached value inside the TTL")
	}
	*now = now.Add(6 * time.Second)
	if got, _ := s.Get(t.Context()); got.Registration != "closed" {
		t.Fatalf("after TTL: %q", got.Registration)
	}
	// Local updates are visible immediately.
	if _, err := s.Update(t.Context(), "", Patch{Registration: ptr("open")}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(t.Context()); got.Registration != "open" || got.UpdatedBy != nil {
		t.Fatalf("after local update: %+v", got)
	}
}

func TestGuestAccessSetting(t *testing.T) {
	s, repo, spy, _ := newSvc(0)
	got, err := s.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !got.GuestAccess {
		t.Fatalf("default: %+v", got)
	}
	got, err = s.Update(t.Context(), "usr_admin", Patch{GuestAccess: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if got.GuestAccess || !got.ChannelAutoRegister || got.Registration != "invite" {
		t.Fatalf("after patch: %+v", got)
	}
	if repo.row.GuestAccess == nil || *repo.row.GuestAccess || repo.row.ChannelAutoRegister != nil {
		t.Fatalf("stored: %+v", repo.row)
	}
	oldV, newV := spy.metas[0]["old"].(map[string]any), spy.metas[0]["new"].(map[string]any)
	if len(oldV) != 1 || oldV["guest_access"] != true || newV["guest_access"] != false {
		t.Fatalf("audit diff: old=%v new=%v", oldV, newV)
	}
}

func TestGuestVoiceSetting(t *testing.T) {
	s, repo, spy, _ := newSvc(0)
	got, err := s.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got.GuestVoice {
		t.Fatalf("default must be off: %+v", got)
	}
	got, err = s.Update(t.Context(), "usr_admin", Patch{GuestVoice: ptr(true)})
	if err != nil {
		t.Fatal(err)
	}
	if !got.GuestVoice || !got.GuestAccess {
		t.Fatalf("after patch: %+v", got)
	}
	if repo.row.GuestVoice == nil || !*repo.row.GuestVoice || repo.row.GuestAccess != nil {
		t.Fatalf("stored: %+v", repo.row)
	}
	oldV, newV := spy.metas[0]["old"].(map[string]any), spy.metas[0]["new"].(map[string]any)
	if len(oldV) != 1 || oldV["guest_voice"] != false || newV["guest_voice"] != true {
		t.Fatalf("audit diff: old=%v new=%v", oldV, newV)
	}
	// File mode carries it too.
	s.SetFile(&config.AccountConfig{GuestAccess: true, GuestVoice: true})
	if got, _ := s.Get(t.Context()); got.Source != SourceFile || !got.GuestVoice {
		t.Fatalf("file mode: %+v", got)
	}
}

func TestFileMode(t *testing.T) {
	s, repo, spy, _ := newSvc(time.Hour)
	// A database override exists from before the config file.
	if _, err := s.Update(t.Context(), "usr_admin", Patch{Registration: ptr("closed")}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(t.Context()); got.Source != SourceDB || got.Registration != "closed" {
		t.Fatalf("%+v", got)
	}
	file := config.AccountConfig{Registration: "open", RequireEmailVerification: false, ChannelCreation: "admins",
		VoiceChannelCreation: "registered", ChannelAutoRegister: false, ChannelExpiryDays: 9, GuestAccess: false}
	s.SetFile(&file)
	file.Registration = "invite" // SetFile copies
	reads := repo.reads
	got, err := s.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// The file wins over network_settings; no database read.
	if got.Source != SourceFile || got.Registration != "open" || got.RequireEmailVerification || got.ChannelCreation != "admins" ||
		got.VoiceChannelCreation != "registered" || got.ChannelAutoRegister || got.ChannelExpiryDays != 9 || got.GuestAccess {
		t.Fatalf("%+v", got)
	}
	if repo.reads != reads {
		t.Fatal("file mode must not read the database")
	}
	_, err = s.Update(t.Context(), "usr_admin", Patch{Registration: ptr("closed")})
	if e, ok := apperr.As(err); !ok || e.Status != 409 || e.Code != "managed_by_config_file" {
		t.Fatalf("want 409 managed_by_config_file, got %v", err)
	}
	if len(spy.events) != 1 {
		t.Fatal("a refused update is not audited", spy.events)
	}
	// Back to database mode (file removed): the stored override applies again at once.
	s.SetFile(nil)
	if got, _ := s.Get(t.Context()); got.Source != SourceDB || got.Registration != "closed" {
		t.Fatalf("%+v", got)
	}
}

// Without a mail server email verification is off (effective), whatever
// the setting says; the warning is logged once per loss of the mailer.
func TestEmailNotConfigured(t *testing.T) {
	s, _, _, _ := newSvc(time.Minute)
	var configured atomic.Bool
	s.EmailConfigured = configured.Load
	var buf bytes.Buffer
	ctx := logger.WithLogger(t.Context(), zerolog.New(&buf))
	warnings := func() int { return strings.Count(buf.String(), "email verification is OFF") }

	for i := 0; i < 3; i++ {
		got, err := s.Get(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !got.RequireEmailVerification || got.RequireEmailVerificationEffective || got.EmailConfigured {
			t.Fatalf("no mail server: %+v", got)
		}
	}
	if warnings() != 1 {
		t.Fatalf("warnings = %d, want 1: %s", warnings(), buf.String())
	}

	configured.Store(true) // e.g. auth.smtp.host set in the config file
	got, _ := s.Get(ctx)
	if !got.RequireEmailVerificationEffective || !got.EmailConfigured {
		t.Fatalf("mail server: %+v", got)
	}
	configured.Store(false)
	got, _ = s.Get(ctx)
	if got.RequireEmailVerificationEffective {
		t.Fatalf("mail server gone: %+v", got)
	}
	if warnings() != 2 {
		t.Fatalf("warnings = %d, want 2 (logged again after the mailer came back and went)", warnings())
	}

	// Setting off: nothing to override, nothing logged.
	upd, err := s.Update(ctx, "usr_admin", Patch{RequireEmailVerification: ptr(false)})
	if err != nil || upd.EmailConfigured || upd.RequireEmailVerificationEffective {
		t.Fatalf("update: %+v %v", upd, err)
	}

	// File mode too.
	s.SetFile(&config.AccountConfig{Registration: "open", RequireEmailVerification: true})
	if got, _ := s.Get(ctx); got.Source != SourceFile || got.RequireEmailVerificationEffective {
		t.Fatalf("file mode: %+v", got)
	}
}

// With the NickServ backend the services verify: the setting applies
// without auth's mailer.
func TestEmailNotConfiguredServicesVerify(t *testing.T) {
	s, _, _, _ := newSvc(0)
	s.EmailConfigured = func() bool { return false }
	s.ServicesVerifyEmail = true
	got, err := s.Get(t.Context())
	if err != nil || got.EmailConfigured || !got.RequireEmailVerificationEffective {
		t.Fatalf("nickserv: %+v %v", got, err)
	}
	// No EmailConfigured func: email works.
	s.EmailConfigured, s.ServicesVerifyEmail = nil, false
	if got, _ := s.Get(t.Context()); !got.EmailConfigured || !got.RequireEmailVerificationEffective {
		t.Fatalf("default: %+v", got)
	}
}
