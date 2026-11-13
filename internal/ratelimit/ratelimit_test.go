package ratelimit

import (
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestBurstThenRefill(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	l := New(3, 6, WithClock(c.now)) // 3 burst, one token per 10s
	for i := range 3 {
		if ok, _ := l.Allow("ip:1"); !ok {
			t.Fatalf("request %d denied within burst", i)
		}
	}
	ok, retry := l.Allow("ip:1")
	if ok {
		t.Fatal("4th request allowed")
	}
	if retry <= 9*time.Second || retry > 10*time.Second {
		t.Fatalf("retry-after = %v, want ~10s", retry)
	}
	if ok, _ := l.Allow("ip:2"); !ok {
		t.Fatal("keys must be independent")
	}
	c.add(10 * time.Second)
	if ok, _ := l.Allow("ip:1"); !ok {
		t.Fatal("token not refilled after 10s")
	}
	if ok, _ := l.Allow("ip:1"); ok {
		t.Fatal("only one token should have refilled")
	}
	c.add(time.Hour)
	for range 3 {
		if ok, _ := l.Allow("ip:1"); !ok {
			t.Fatal("bucket must refill up to burst")
		}
	}
	if ok, _ := l.Allow("ip:1"); ok {
		t.Fatal("refill must cap at burst")
	}
}

func TestPrune(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	l := New(2, 60, WithClock(c.now))
	l.Allow("a")
	l.Allow("b")
	l.Prune()
	if l.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (not yet refilled)", l.Len())
	}
	c.add(2 * time.Second)
	l.Prune()
	if l.Len() != 0 {
		t.Fatalf("Len = %d after refill, want 0", l.Len())
	}
}

func TestConcurrent(t *testing.T) {
	l := New(100, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				if ok, _ := l.Allow("k"); ok {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if allowed != 100 {
		t.Fatalf("allowed %d of 200, want exactly 100", allowed)
	}
}
