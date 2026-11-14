package settings

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	auditrepo "github.com/boson-chat/auth/internal/db/repositories/audit"
	settingsrepo "github.com/boson-chat/auth/internal/db/repositories/settings"
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
		ChannelCreation: "registered", VoiceChannelCreation: "founders", ChannelAutoRegister: true, ChannelExpiryDays: 0,
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
