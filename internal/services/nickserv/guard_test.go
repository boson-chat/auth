package nickserv

import (
	"context"
	"testing"
	"time"
)

func TestGuardLockout(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	g := NewGuard(GuardConfig{
		AccountBurst: 100, AccountPerMinute: 100, IPBurst: 100, IPPerMinute: 100,
		AccountThreshold: 3, IPThreshold: 5, Window: 10 * time.Minute, LockFor: 15 * time.Minute,
	}, NewMemoryLockouts(), clock)
	ctx := context.Background()
	allow := func(acct, ip string) *Denial {
		t.Helper()
		d, err := g.Allow(ctx, acct, ip)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	// Two failures, then a window passes: the count starts over.
	_ = g.Failed(ctx, "alice", "192.0.2.1")
	_ = g.Failed(ctx, "alice", "192.0.2.1")
	now = now.Add(11 * time.Minute)
	_ = g.Failed(ctx, "alice", "192.0.2.1")
	if d := allow("alice", "192.0.2.1"); d != nil {
		t.Fatalf("locked after failures in two windows: %+v", d)
	}
	// Three within the window lock the account (not other accounts).
	_ = g.Failed(ctx, "alice", "192.0.2.2")
	_ = g.Failed(ctx, "alice", "192.0.2.2")
	d := allow("alice", "198.51.100.9")
	if d == nil || !d.Locked || d.RetryAfter != 15*time.Minute {
		t.Fatalf("want a 15m lock, got %+v", d)
	}
	if d := allow("bob", "198.51.100.9"); d != nil {
		t.Fatalf("bob locked: %+v", d)
	}
	now = now.Add(16 * time.Minute)
	if d := allow("alice", "198.51.100.9"); d != nil {
		t.Fatalf("still locked after the lock ended: %+v", d)
	}
	// One IP failing on many accounts gets locked by the IP threshold.
	for i, a := range []string{"a", "b", "c", "d", "e"} {
		_ = g.Failed(ctx, a, "203.0.113.7")
		if i < 4 {
			if d := allow("zed", "203.0.113.7"); d != nil {
				t.Fatalf("IP locked too early (%d): %+v", i, d)
			}
		}
	}
	if d := allow("zed", "203.0.113.7"); d == nil || !d.Locked {
		t.Fatal("IP not locked after 5 failures")
	}
	// Success resets the account's failures.
	_ = g.Failed(ctx, "carol", "")
	_ = g.Failed(ctx, "carol", "")
	_ = g.Succeeded(ctx, "carol")
	_ = g.Failed(ctx, "carol", "")
	_ = g.Failed(ctx, "carol", "")
	if d := allow("carol", ""); d != nil {
		t.Fatalf("success didn't reset: %+v", d)
	}
}

func TestGuardRateLimit(t *testing.T) {
	g := NewGuard(GuardConfig{AccountBurst: 2, AccountPerMinute: 1, IPBurst: 3, IPPerMinute: 1}, NewMemoryLockouts(), nil)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if d, _ := g.Allow(ctx, "alice", "192.0.2.1"); d != nil {
			t.Fatalf("attempt %d denied", i)
		}
	}
	if d, _ := g.Allow(ctx, "alice", "192.0.2.2"); d == nil || d.Locked || d.RetryAfter <= 0 {
		t.Fatalf("account bucket: %+v", d)
	}
	if d, _ := g.Allow(ctx, "bob", "192.0.2.1"); d != nil {
		t.Fatalf("bob on the same IP (3rd of 3): %+v", d)
	}
	if d, _ := g.Allow(ctx, "carol", "192.0.2.1"); d == nil {
		t.Fatal("IP bucket not applied")
	}
}
