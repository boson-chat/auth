package social

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestHubPoll(t *testing.T) {
	now := time.Unix(1000, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	h := NewHub(clock)
	ctx := context.Background()

	if h.Online("u") {
		t.Fatal("online before polling")
	}
	// No cursor: reset at once.
	ev, cur, reset := h.Poll(ctx, "u", "", time.Second)
	if !reset || len(ev) != 0 {
		t.Fatalf("first poll %v %v", ev, reset)
	}
	if !h.Online("u") {
		t.Fatal("offline right after a poll")
	}
	// Queued while away: returned at once.
	h.Publish("u", EventFriends, nil)
	h.Publish("other", EventFriends, nil)
	ev, cur2, reset := h.Poll(ctx, "u", cur, time.Second)
	if reset || len(ev) != 1 || ev[0].Type != EventFriends || ev[0].Seq != 1 {
		t.Fatalf("queued %v %v", ev, reset)
	}
	// Waiting: woken by a publish.
	done := make(chan []Event)
	go func() {
		ev, _, _ := h.Poll(ctx, "u", cur2, 5*time.Second)
		done <- ev
	}()
	time.Sleep(50 * time.Millisecond)
	if !h.Online("u") {
		t.Fatal("offline while a poll waits")
	}
	h.Publish("u", EventMissed, MissedEvent{Count: 2})
	select {
	case ev := <-done:
		if len(ev) != 1 || ev[0].Type != EventMissed {
			t.Fatalf("woken with %v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("poll not woken")
	}
	// Nothing new: the wait ends empty.
	ev, _, reset = h.Poll(ctx, "u", h.cursor(2), 30*time.Millisecond)
	if reset || len(ev) != 0 {
		t.Fatalf("timeout %v %v", ev, reset)
	}
	// A cursor from another process: reset.
	if _, _, reset := h.Poll(ctx, "u", "deadbeef.2", time.Second); !reset {
		t.Fatal("foreign epoch accepted")
	}
	// A cursor older than the queue: reset.
	for range queueLen + 5 {
		h.Publish("u", EventFriends, nil)
	}
	if _, _, reset := h.Poll(ctx, "u", h.cursor(2), time.Second); !reset {
		t.Fatal("stale cursor accepted")
	}
	// Offline after the grace, then pruned.
	mu.Lock()
	now = now.Add(OnlineGrace + time.Second)
	mu.Unlock()
	if h.Online("u") {
		t.Fatal("online long after the last poll")
	}
	mu.Lock()
	now = now.Add(idleDrop)
	mu.Unlock()
	h.Prune()
	if len(h.users) != 0 {
		t.Fatalf("not pruned: %v", h)
	}
}

func TestHubPollCancelled(t *testing.T) {
	h := NewHub(nil)
	_, cur, _ := h.Poll(context.Background(), "u", "", time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	start := time.Now()
	if ev, _, _ := h.Poll(ctx, "u", cur, 5*time.Second); len(ev) != 0 || time.Since(start) > time.Second {
		t.Fatalf("cancelled poll: %v after %v", ev, time.Since(start))
	}
}
