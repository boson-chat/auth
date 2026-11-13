// Package ratelimit is an in-memory keyed token-bucket limiter.
//
// State is per process: with several replicas each enforces its own limits,
// which is acceptable for brute-force damping behind a single proxy.
package ratelimit

import (
	"context"
	"math"
	"sync"
	"time"
)

// Limiter holds one token bucket per key.
type Limiter struct {
	rate  float64 // tokens per second
	burst float64
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Option configures a Limiter.
type Option func(*Limiter)

// WithClock overrides time.Now (tests).
func WithClock(now func() time.Time) Option { return func(l *Limiter) { l.now = now } }

// New returns a limiter allowing burst requests at once and perMinute sustained.
func New(burst int, perMinute float64, opts ...Option) *Limiter {
	l := &Limiter{
		rate:    perMinute / 60,
		burst:   float64(max(burst, 1)),
		now:     time.Now,
		buckets: make(map[string]*bucket),
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

// Allow takes one token for key. When none is left it returns false and how
// long until one is available.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	l.refill(b, now)
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	if l.rate <= 0 {
		return false, time.Hour
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

func (l *Limiter) refill(b *bucket, now time.Time) {
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+el*l.rate)
		b.last = now
	}
}

// Prune drops buckets that have refilled completely; they behave exactly
// like a missing bucket.
func (l *Limiter) Prune() {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		l.refill(b, now)
		if b.tokens >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// Len is the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// RunPruner prunes every interval until ctx is done.
func (l *Limiter) RunPruner(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.Prune()
		}
	}
}
