package session_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	auditrepo "github.com/boson-chat/auth/internal/db/repositories/audit"
	"github.com/boson-chat/auth/internal/db/repositories/refreshtoken"
	sessionrepo "github.com/boson-chat/auth/internal/db/repositories/session"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/opaque"
	"github.com/boson-chat/auth/internal/reqmeta"
	"github.com/boson-chat/auth/internal/services/session"
	"github.com/boson-chat/auth/metrics"
)

// ---- in-memory fakes -------------------------------------------------------

type store struct {
	mu       sync.Mutex
	sessions map[string]*sessionrepo.Session
	tokens   map[string]*refreshtoken.RefreshToken // by id
	users    map[string]*user.User
	// users.RecordSignIn / TouchActive bookkeeping.
	signInWrites, activeCalls, activeWrites int
}

func newStore() *store {
	return &store{sessions: map[string]*sessionrepo.Session{}, tokens: map[string]*refreshtoken.RefreshToken{}, users: map[string]*user.User{}}
}

type sessions struct{ *store }

func (s sessions) Create(_ context.Context, x *sessionrepo.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *x
	s.sessions[x.ID] = &c
	return nil
}
func (s sessions) FindByID(_ context.Context, id string) (*sessionrepo.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sessions[id]
	if !ok {
		return nil, repositories.ErrNotFound
	}
	c := *x
	return &c, nil
}
func (s sessions) FindByIDForUpdate(ctx context.Context, id string) (*sessionrepo.Session, error) {
	return s.FindByID(ctx, id)
}
func (s sessions) ListActiveByUser(_ context.Context, uid string, now time.Time) ([]*sessionrepo.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*sessionrepo.Session
	for _, x := range s.sessions {
		if x.UserID == uid && x.Active(now) {
			c := *x
			out = append(out, &c)
		}
	}
	return out, nil
}
func (s sessions) Touch(_ context.Context, id string, at time.Time, ip, ua string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id].LastSeenAt = at
	return nil
}
func (s sessions) Revoke(_ context.Context, id string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sessions[id]
	if !ok || x.RevokedAt != nil {
		return false, nil
	}
	x.RevokedAt = &at
	return true, nil
}
func (s sessions) RevokeAllForUser(_ context.Context, uid, except string, at time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, x := range s.sessions {
		if x.UserID == uid && x.ID != except && x.RevokedAt == nil {
			x.RevokedAt = &at
			n++
		}
	}
	return n, nil
}
func (s sessions) DeleteExpiredBefore(context.Context, time.Time) (int64, error) { return 0, nil }

type tokens struct{ *store }

func (s tokens) Create(_ context.Context, t *refreshtoken.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *t
	s.tokens[t.ID] = &c
	return nil
}
func (s tokens) FindByHash(_ context.Context, h []byte) (*refreshtoken.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if string(t.TokenHash) == string(h) {
			c := *t
			return &c, nil
		}
	}
	return nil, repositories.ErrNotFound
}
func (s tokens) FindByHashForUpdate(ctx context.Context, h []byte) (*refreshtoken.RefreshToken, error) {
	return s.FindByHash(ctx, h)
}
func (s tokens) MarkUsed(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[id].UsedAt = &at
	return nil
}
func (s tokens) revokeWhere(at time.Time, f func(*refreshtoken.RefreshToken) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if f(t) && t.RevokedAt == nil {
			t.RevokedAt = &at
		}
	}
}
func (s tokens) RevokeFamily(_ context.Context, fam string, at time.Time) error {
	s.revokeWhere(at, func(t *refreshtoken.RefreshToken) bool { return t.FamilyID == fam })
	return nil
}
func (s tokens) RevokeBySession(_ context.Context, sid string, at time.Time) error {
	s.revokeWhere(at, func(t *refreshtoken.RefreshToken) bool { return t.SessionID == sid })
	return nil
}
func (s tokens) RevokeByUser(_ context.Context, uid, except string, at time.Time) error {
	s.mu.Lock()
	owned := map[string]bool{}
	for _, x := range s.sessions {
		if x.UserID == uid && x.ID != except {
			owned[x.ID] = true
		}
	}
	s.mu.Unlock()
	s.revokeWhere(at, func(t *refreshtoken.RefreshToken) bool { return owned[t.SessionID] })
	return nil
}
func (s tokens) DeleteExpiredBefore(context.Context, time.Time) (int64, error) { return 0, nil }

type users struct {
	*store
	user.UserRepositoryImpl // unused methods panic via nil interface
}

func (s users) FindByID(_ context.Context, id string) (*user.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, repositories.ErrNotFound
	}
	c := *u
	return &c, nil
}

func (s users) RecordSignIn(_ context.Context, id string, at time.Time, method, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return repositories.ErrNotFound
	}
	s.signInWrites++
	u.LastSignInAt, u.LastSignInMethod, u.LastSignInIP = &at, &method, &ip
	if u.LastActiveAt == nil || at.After(*u.LastActiveAt) {
		u.LastActiveAt = &at
	}
	return nil
}

func (s users) TouchActive(_ context.Context, id string, at time.Time, minAge time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeCalls++
	u, ok := s.users[id]
	if !ok || (u.LastActiveAt != nil && u.LastActiveAt.After(at.Add(-minAge))) {
		return false, nil
	}
	s.activeWrites++
	u.LastActiveAt = &at
	return true, nil
}

type auditLog struct {
	mu     sync.Mutex
	events []string
}

func (a *auditLog) Record(_ context.Context, _, event string, _ map[string]any) {
	a.mu.Lock()
	a.events = append(a.events, event)
	a.mu.Unlock()
}
func (a *auditLog) RecordTarget(ctx context.Context, actor, _, event string, meta map[string]any) {
	a.Record(ctx, actor, event, meta)
}
func (a *auditLog) List(context.Context, auditrepo.Filter) ([]*auditrepo.EntryView, error) {
	return nil, nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ---- tests -----------------------------------------------------------------

func setup(t *testing.T) (session.SessionServiceImpl, *store, *auditLog, *clock) {
	t.Helper()
	st := newStore()
	st.users["usr_a"] = &user.User{ID: "usr_a", Username: "alice", Role: user.RoleUser}
	a := &auditLog{}
	c := &clock{t: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	svc := session.NewSessionService(sessions{st}, tokens{st}, users{store: st}, db.NoTx{}, a, metrics.Noop(),
		session.Options{RefreshTTL: 24 * time.Hour, SessionMaxAge: 72 * time.Hour, Now: c.Now})
	return svc, st, a, c
}

func TestRefreshRotates(t *testing.T) {
	ctx := context.Background()
	svc, st, _, c := setup(t)
	iss, err := svc.Create(ctx, "usr_a", session.MethodPassword)
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range st.tokens {
		if string(tk.TokenHash) != string(opaque.Hash(iss.RefreshToken)) {
			t.Fatal("stored hash does not match")
		}
		if string(tk.TokenHash) == iss.RefreshToken {
			t.Fatal("plaintext refresh token stored")
		}
	}
	c.Add(time.Hour)
	next, u, err := svc.Refresh(ctx, iss.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "usr_a" || next.Session.ID != iss.Session.ID || next.RefreshToken == iss.RefreshToken {
		t.Fatalf("bad rotation: %+v", next)
	}
	if !next.RefreshExpiresAt.Equal(c.Now().Add(24 * time.Hour)) {
		t.Fatalf("refresh exp = %v", next.RefreshExpiresAt)
	}
	// Chain keeps working.
	if _, _, err := svc.Refresh(ctx, next.RefreshToken); err != nil {
		t.Fatalf("second rotation: %v", err)
	}
}

func TestReuseRevokesFamilyAndSession(t *testing.T) {
	ctx := context.Background()
	svc, st, a, _ := setup(t)
	iss, _ := svc.Create(ctx, "usr_a", session.MethodPassword)
	other, _ := svc.Create(ctx, "usr_a", session.MethodPassword)
	next, _, err := svc.Refresh(ctx, iss.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}

	// The old token is presented again (stolen copy).
	_, _, err = svc.Refresh(ctx, iss.RefreshToken)
	if !errors.Is(err, session.ErrRefreshReuse) || !errors.Is(err, apperr.ErrInvalidRefresh) {
		t.Fatalf("reuse err = %v", err)
	}
	if st.sessions[iss.Session.ID].RevokedAt == nil {
		t.Fatal("session not revoked on reuse")
	}
	for _, tk := range st.tokens {
		if tk.SessionID == iss.Session.ID && tk.RevokedAt == nil {
			t.Fatal("family token left unrevoked")
		}
	}
	// The legitimate newest token is dead too.
	if _, _, err := svc.Refresh(ctx, next.RefreshToken); !errors.Is(err, apperr.ErrInvalidRefresh) {
		t.Fatalf("newest token after reuse: %v", err)
	}
	if _, err := svc.Validate(ctx, iss.Session.ID, "usr_a"); err == nil {
		t.Fatal("revoked session still validates")
	}
	// Other sessions are untouched.
	if _, _, err := svc.Refresh(ctx, other.RefreshToken); err != nil {
		t.Fatalf("unrelated session affected: %v", err)
	}
	found := false
	for _, e := range a.events {
		found = found || e == "refresh_token_reuse"
	}
	if !found {
		t.Fatal("reuse not audited")
	}
}

func TestRefreshRejects(t *testing.T) {
	ctx := context.Background()
	svc, st, _, c := setup(t)

	if _, _, err := svc.Refresh(ctx, "bsr_unknown"); !errors.Is(err, apperr.ErrInvalidRefresh) {
		t.Fatalf("unknown: %v", err)
	}
	if _, _, err := svc.Refresh(ctx, ""); !errors.Is(err, apperr.ErrInvalidRefresh) {
		t.Fatalf("empty: %v", err)
	}

	iss, _ := svc.Create(ctx, "usr_a", session.MethodPassword)
	c.Add(25 * time.Hour)
	if _, _, err := svc.Refresh(ctx, iss.RefreshToken); !errors.Is(err, apperr.ErrInvalidRefresh) {
		t.Fatalf("expired: %v", err)
	}

	iss, _ = svc.Create(ctx, "usr_a", session.MethodPassword)
	if err := svc.Revoke(ctx, "usr_a", iss.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Refresh(ctx, iss.RefreshToken); !errors.Is(err, apperr.ErrInvalidRefresh) || errors.Is(err, session.ErrRefreshReuse) {
		t.Fatalf("revoked session: %v", err)
	}

	iss, _ = svc.Create(ctx, "usr_a", session.MethodPassword)
	now := c.Now()
	st.users["usr_a"].DisabledAt = &now
	if _, _, err := svc.Refresh(ctx, iss.RefreshToken); !errors.Is(err, apperr.ErrAccountDisabled) {
		t.Fatalf("disabled user: %v", err)
	}
	if st.sessions[iss.Session.ID].RevokedAt == nil {
		t.Fatal("disabled user's session should be revoked on refresh")
	}
}

func TestSessionMaxAgeCapsRefresh(t *testing.T) {
	ctx := context.Background()
	svc, _, _, c := setup(t)
	iss, _ := svc.Create(ctx, "usr_a", session.MethodPassword)
	raw := iss.RefreshToken
	for range 3 { // 3 × 23h = 69h of the 72h max age
		c.Add(23 * time.Hour)
		next, _, err := svc.Refresh(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		raw = next.RefreshToken
		if next.RefreshExpiresAt.After(iss.Session.ExpiresAt) {
			t.Fatal("refresh token outlives its session")
		}
	}
	c.Add(4 * time.Hour)
	if _, _, err := svc.Refresh(ctx, raw); err == nil {
		t.Fatal("refresh past session max age")
	}
}

func TestRevokeOwnership(t *testing.T) {
	ctx := context.Background()
	svc, st, _, _ := setup(t)
	st.users["usr_b"] = &user.User{ID: "usr_b", Username: "bob"}
	iss, _ := svc.Create(ctx, "usr_a", session.MethodPassword)
	if err := svc.Revoke(ctx, "usr_b", iss.Session.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("revoking someone else's session: %v", err)
	}
	if _, err := svc.Validate(ctx, iss.Session.ID, "usr_a"); err != nil {
		t.Fatal("session must survive a foreign revoke attempt")
	}
	if _, err := svc.Validate(ctx, iss.Session.ID, "usr_b"); err == nil {
		t.Fatal("session validated for the wrong user")
	}
}

func TestCreateRecordsSignIn(t *testing.T) {
	svc, st, _, c := setup(t)
	ctx := reqmeta.With(context.Background(), reqmeta.Meta{IP: "203.0.113.7", UserAgent: "test"})
	if _, err := svc.Create(ctx, "usr_a", "oidc:corp"); err != nil {
		t.Fatal(err)
	}
	u := st.users["usr_a"]
	if u.LastSignInAt == nil || !u.LastSignInAt.Equal(c.Now()) {
		t.Fatalf("last_sign_in_at = %v, want %v", u.LastSignInAt, c.Now())
	}
	if *u.LastSignInMethod != "oidc:corp" || *u.LastSignInIP != "203.0.113.7" {
		t.Fatalf("method/ip = %q/%q", *u.LastSignInMethod, *u.LastSignInIP)
	}
	if u.LastActiveAt == nil || !u.LastActiveAt.Equal(c.Now()) {
		t.Fatalf("last_active_at = %v: a sign-in counts as activity", u.LastActiveAt)
	}
	// A later sign-in overwrites.
	c.Add(time.Hour)
	if _, err := svc.Create(ctx, "usr_a", session.MethodPassword); err != nil {
		t.Fatal(err)
	}
	if !u.LastSignInAt.Equal(c.Now()) || *u.LastSignInMethod != session.MethodPassword || st.signInWrites != 2 {
		t.Fatalf("second sign-in: at=%v method=%q writes=%d", u.LastSignInAt, *u.LastSignInMethod, st.signInWrites)
	}
}

func TestCreateUnknownUserFails(t *testing.T) {
	svc, st, _, _ := setup(t)
	if _, err := svc.Create(context.Background(), "usr_missing", session.MethodPassword); !errors.Is(err, repositories.ErrNotFound) {
		t.Fatalf("err = %v, want not found", err)
	}
	if len(st.sessions) != 0 {
		t.Fatal("no session may be created for a missing user")
	}
}

func TestRefreshTouchesActivityThrottled(t *testing.T) {
	ctx := context.Background()
	svc, st, _, c := setup(t)
	iss, err := svc.Create(ctx, "usr_a", session.MethodPassword)
	if err != nil {
		t.Fatal(err)
	}
	signIn := c.Now()
	u := st.users["usr_a"]
	refresh := func() {
		t.Helper()
		next, _, err := svc.Refresh(ctx, iss.RefreshToken)
		if err != nil {
			t.Fatal(err)
		}
		iss = next
	}

	// Within the interval: no query at all (the loaded user is fresh).
	c.Add(session.ActivityInterval - time.Second)
	refresh()
	if st.activeCalls != 0 || !u.LastActiveAt.Equal(signIn) {
		t.Fatalf("throttled refresh: calls=%d last_active=%v", st.activeCalls, u.LastActiveAt)
	}
	if !st.sessions[iss.Session.ID].LastSeenAt.Equal(c.Now()) {
		t.Fatal("session last_seen_at must still move on every refresh")
	}

	// Past the interval: one write.
	c.Add(2 * time.Second)
	refresh()
	if st.activeWrites != 1 || !u.LastActiveAt.Equal(c.Now()) {
		t.Fatalf("refresh after interval: writes=%d last_active=%v want %v", st.activeWrites, u.LastActiveAt, c.Now())
	}
	bumped := c.Now()

	// Straight away again: skipped.
	c.Add(time.Minute)
	refresh()
	if st.activeWrites != 1 || !u.LastActiveAt.Equal(bumped) {
		t.Fatalf("second refresh within interval wrote: writes=%d", st.activeWrites)
	}
	// Refresh never counts as a sign-in.
	if st.signInWrites != 1 || !u.LastSignInAt.Equal(signIn) {
		t.Fatalf("refresh changed last_sign_in_at: %v (writes %d)", u.LastSignInAt, st.signInWrites)
	}
}
