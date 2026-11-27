package bridge

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boson-chat/auth/internal/services/bridge/bridgetest"
)

func guestService(t *testing.T, fb *bridgetest.Bridge, guests *atomic.Bool) (*Service, *syncBuffer) {
	t.Helper()
	s, logs := newTestService(t, fb.URL(), &memStore{}, "", "")
	s.Client = NewHTTPClient(fb.URL(), fb.Token, time.Second, nil)
	s.Config.PollInterval = 10 * time.Millisecond
	s.GuestAccess = func(context.Context) (bool, error) { return guests.Load(), nil }
	return s, logs
}

func settingsPuts(fb *bridgetest.Bridge) int {
	n := 0
	for _, c := range fb.Calls() {
		if c.Method == "PUT" && strings.HasSuffix(c.Name, "settings") {
			n++
		}
	}
	return n
}

func TestSyncGuests(t *testing.T) {
	fb := bridgetest.New("tok")
	t.Cleanup(fb.Close)
	var guests atomic.Bool
	guests.Store(true)
	s, logs := guestService(t, fb, &guests)
	ctx := context.Background()
	now := time.Unix(1000, 0)
	var st guestSync

	// First check: sent.
	if w := s.syncGuests(ctx, &st, now); w != s.Config.PollInterval {
		t.Fatalf("wait %v", w)
	}
	if on, set := fb.Guests(); !on || !set {
		t.Fatalf("bridge guests %v %v", on, set)
	}
	if settingsPuts(fb) != 1 || !strings.Contains(logs.String(), "guest setting sent") {
		t.Fatalf("calls/logs: %s", logs)
	}
	// Unchanged: nothing sent.
	s.syncGuests(ctx, &st, now.Add(time.Second))
	if n := settingsPuts(fb); n != 0 {
		t.Fatalf("unchanged setting sent %d times", n)
	}
	// Changed: sent at once.
	guests.Store(false)
	s.syncGuests(ctx, &st, now.Add(2*time.Second))
	if on, set := fb.Guests(); on || !set {
		t.Fatalf("bridge guests after change %v %v", on, set)
	}
	// Resync after the reconcile interval (10m default here: 0 → 10m).
	s.syncGuests(ctx, &st, now.Add(3*time.Second))
	if settingsPuts(fb) != 1 {
		t.Fatal("expected one PUT for the change, none for the unchanged check")
	}
	s.syncGuests(ctx, &st, now.Add(2*time.Second+s.guestResync()))
	if settingsPuts(fb) != 1 {
		t.Fatal("no resync")
	}
	s.Config.ReconcileInterval = time.Hour
	if s.guestResync() != time.Hour {
		t.Fatal("resync should follow the reconcile interval")
	}
}

func TestSyncGuestsBridgeDownThenUp(t *testing.T) {
	fb := bridgetest.New("tok")
	t.Cleanup(fb.Close)
	var guests atomic.Bool
	guests.Store(true)
	s, logs := guestService(t, fb, &guests)
	s.Config.RetryMin, s.Config.RetryMax = time.Second, time.Hour
	ctx := context.Background()
	var st guestSync
	fb.Down.Store(true)
	waits := []time.Duration{}
	for i := 0; i < 8; i++ {
		waits = append(waits, s.syncGuests(ctx, &st, time.Now()))
	}
	if waits[0] != time.Second || waits[1] != 2*time.Second || waits[7] != guestRetryMax {
		t.Fatalf("backoff %v", waits)
	}
	if strings.Count(logs.String(), `"level":"warn"`) != 1 {
		t.Fatalf("want one warning while down: %s", logs)
	}
	fb.Down.Store(false)
	if w := s.syncGuests(ctx, &st, time.Now()); w != s.Config.PollInterval || st.failures != 0 {
		t.Fatalf("after recovery wait %v state %+v", w, st)
	}
	if on, _ := fb.Guests(); !on {
		t.Fatal("not sent after the bridge came up")
	}
}

func TestSyncGuestsOldEvrd(t *testing.T) {
	fb := bridgetest.New("tok")
	t.Cleanup(fb.Close)
	fb.NoSettings.Store(true)
	var guests atomic.Bool
	s, logs := guestService(t, fb, &guests)
	ctx := context.Background()
	var st guestSync
	now := time.Now()
	for i := 0; i < 3; i++ {
		guests.Store(i%2 == 0) // a change each time: asked again, logged once
		if w := s.syncGuests(ctx, &st, now); w != s.Config.PollInterval {
			t.Fatalf("404 backed off: %v", w)
		}
	}
	if n := strings.Count(logs.String(), "evrd before 0.61"); n != 1 {
		t.Fatalf("logged %d times: %s", n, logs)
	}
	if strings.Contains(logs.String(), `"level":"warn"`) {
		t.Fatalf("404 warned: %s", logs)
	}
	// Upgraded: the next change is sent, and logged at info.
	fb.NoSettings.Store(false)
	guests.Store(!guests.Load())
	s.syncGuests(ctx, &st, now)
	if _, set := fb.Guests(); !set || st.unsupported {
		t.Fatalf("not sent after the upgrade: %+v", st)
	}
}

func TestSyncGuestsSettingError(t *testing.T) {
	fb := bridgetest.New("tok")
	t.Cleanup(fb.Close)
	var guests atomic.Bool
	s, logs := guestService(t, fb, &guests)
	s.GuestAccess = func(context.Context) (bool, error) { return false, errors.New("db down") }
	var st guestSync
	if w := s.syncGuests(context.Background(), &st, time.Now()); w != s.Config.PollInterval {
		t.Fatalf("wait %v", w)
	}
	if settingsPuts(fb) != 0 || !strings.Contains(logs.String(), "reading the guest setting") {
		t.Fatalf("logs %s", logs)
	}
}

func TestRunGuests(t *testing.T) {
	fb := bridgetest.New("tok")
	t.Cleanup(fb.Close)
	var guests atomic.Bool
	s, _ := guestService(t, fb, &guests)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.RunGuests(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for _, want := range []bool{false, true, false} {
		guests.Store(want)
		for {
			if on, set := fb.Guests(); set && on == want {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("bridge never got guests=%v", want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	<-done
	// Without GuestAccess: returns at once.
	s.GuestAccess = nil
	s.RunGuests(context.Background())
}

func TestPutSettingsAnswer(t *testing.T) {
	fb := bridgetest.New("tok")
	t.Cleanup(fb.Close)
	c := NewHTTPClient(fb.URL(), "tok", time.Second, nil)
	on := true
	got, err := c.PutSettings(context.Background(), Settings{Guests: &on})
	if err != nil || got.Guests == nil || !*got.Guests || got.NickGuardGraceSeconds == nil || *got.NickGuardGraceSeconds != 60 ||
		len(got.Set) != 1 || got.Set[0] != "guests" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := NewHTTPClient(fb.URL(), "wrong", time.Second, nil).PutSettings(context.Background(), Settings{Guests: &on}); !IsStatus(err, 401) {
		t.Fatalf("wrong token: %v", err)
	}
}
