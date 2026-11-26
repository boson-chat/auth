package nickserv

import (
	"context"
	"sync"
	"time"

	"github.com/boson-chat/auth/internal/ratelimit"
)

// LockoutStore keeps failed-attempt counters shared by replicas.
type LockoutStore interface {
	// LockedUntil returns when key's lock ends (zero = not locked).
	LockedUntil(ctx context.Context, key string, now time.Time) (time.Time, error)
	// RecordFailure counts a failure for key in a window starting at its
	// first failure; reaching threshold locks key until now+lockFor and
	// starts a new window. Returns the lock end (zero = not locked).
	RecordFailure(ctx context.Context, key string, now time.Time, window time.Duration, threshold int, lockFor time.Duration) (time.Time, error)
	// Reset forgets key's failures.
	Reset(ctx context.Context, key string) error
}

// GuardConfig are the limits of a Guard.
type GuardConfig struct {
	AccountBurst, IPBurst         int
	AccountPerMinute, IPPerMinute float64
	// Failures within Window before an account / IP is locked for
	// LockFor. 0 = no lockout of that kind.
	AccountThreshold, IPThreshold int
	Window, LockFor               time.Duration
}

// Guard rate-limits and locks out verification attempts per account and per
// client IP, before anything reaches the services.
type Guard struct {
	cfg       GuardConfig
	store     LockoutStore
	accountRL *ratelimit.Limiter
	ipRL      *ratelimit.Limiter
	now       func() time.Time
}

// NewGuard makes a Guard; now may be nil.
func NewGuard(cfg GuardConfig, store LockoutStore, now func() time.Time) *Guard {
	if now == nil {
		now = time.Now
	}
	return &Guard{
		cfg: cfg, store: store, now: now,
		accountRL: ratelimit.New(cfg.AccountBurst, cfg.AccountPerMinute),
		ipRL:      ratelimit.New(cfg.IPBurst, cfg.IPPerMinute),
	}
}

// RunPruner drops idle rate-limit buckets until ctx is done.
func (g *Guard) RunPruner(ctx context.Context) {
	go g.accountRL.RunPruner(ctx, time.Minute)
	go g.ipRL.RunPruner(ctx, time.Minute)
}

// Denial says why an attempt may not go ahead.
type Denial struct {
	// Locked: a lockout (else a rate limit).
	Locked     bool
	RetryAfter time.Duration
}

func accountKey(folded string) string { return "a:" + folded }
func ipKey(ip string) string          { return "ip:" + ip }

// Allow checks the lockouts and takes a token from the account and IP
// buckets. A nil Denial means go ahead.
func (g *Guard) Allow(ctx context.Context, folded, ip string) (*Denial, error) {
	now := g.now()
	keys := []string{accountKey(folded)}
	if ip != "" {
		keys = append(keys, ipKey(ip))
	}
	for _, k := range keys {
		until, err := g.store.LockedUntil(ctx, k, now)
		if err != nil {
			return nil, err
		}
		if until.After(now) {
			return &Denial{Locked: true, RetryAfter: until.Sub(now)}, nil
		}
	}
	if ip != "" {
		if ok, wait := g.ipRL.Allow(ip); !ok {
			return &Denial{RetryAfter: wait}, nil
		}
	}
	if ok, wait := g.accountRL.Allow(folded); !ok {
		return &Denial{RetryAfter: wait}, nil
	}
	return nil, nil
}

// Failed records a wrong password.
func (g *Guard) Failed(ctx context.Context, folded, ip string) error {
	now := g.now()
	if g.cfg.AccountThreshold > 0 {
		if _, err := g.store.RecordFailure(ctx, accountKey(folded), now, g.cfg.Window, g.cfg.AccountThreshold, g.cfg.LockFor); err != nil {
			return err
		}
	}
	if ip != "" && g.cfg.IPThreshold > 0 {
		if _, err := g.store.RecordFailure(ctx, ipKey(ip), now, g.cfg.Window, g.cfg.IPThreshold, g.cfg.LockFor); err != nil {
			return err
		}
	}
	return nil
}

// Succeeded forgets the account's failures (the IP's stay: one IP trying
// many accounts is still suspicious).
func (g *Guard) Succeeded(ctx context.Context, folded string) error {
	if g.cfg.AccountThreshold == 0 {
		return nil
	}
	return g.store.Reset(ctx, accountKey(folded))
}

// MemoryLockouts is an in-process LockoutStore (tests, single replica).
type MemoryLockouts struct {
	mu sync.Mutex
	m  map[string]*memLockout
}

type memLockout struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

func NewMemoryLockouts() *MemoryLockouts { return &MemoryLockouts{m: map[string]*memLockout{}} }

func (s *MemoryLockouts) LockedUntil(_ context.Context, key string, now time.Time) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l := s.m[key]; l != nil && l.lockedUntil.After(now) {
		return l.lockedUntil, nil
	}
	return time.Time{}, nil
}

func (s *MemoryLockouts) RecordFailure(_ context.Context, key string, now time.Time, window time.Duration, threshold int, lockFor time.Duration) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.m[key]
	if l == nil {
		l = &memLockout{windowStart: now}
		s.m[key] = l
	}
	f, ws, until := NextLockout(l.failures, l.windowStart, l.lockedUntil, now, window, threshold, lockFor)
	l.failures, l.windowStart, l.lockedUntil = f, ws, until
	if until.After(now) {
		return until, nil
	}
	return time.Time{}, nil
}

func (s *MemoryLockouts) Reset(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

// NextLockout is the lockout state after one more failure: failures within
// window of windowStart count up; reaching threshold locks until
// now+lockFor and restarts the count.
func NextLockout(failures int, windowStart, lockedUntil, now time.Time, window time.Duration, threshold int, lockFor time.Duration) (int, time.Time, time.Time) {
	if failures == 0 || !now.Before(windowStart.Add(window)) {
		failures, windowStart = 0, now
	}
	failures++
	if failures >= threshold {
		return 0, now, now.Add(lockFor)
	}
	return failures, windowStart, lockedUntil
}
