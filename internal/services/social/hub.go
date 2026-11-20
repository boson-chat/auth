package social

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The event feed: what an open app learns without asking (a call ringing,
// its answer, friend list changes, the missed-call count). Apps long-poll
// GET /v1/events through their API proxy, so nothing new has to listen
// anywhere: one request per user is held open for up to PollWait and
// answered as soon as there is something new.
//
// Each user has a short in-memory queue numbered from 1. A cursor is
// "<epoch>.<seq>": the epoch changes when the process restarts, and a
// cursor from another epoch (or one so old its events are gone) is answered
// with reset, after which the app reloads its state (the snapshot).
//
// A user is online (their app is open) while a poll is waiting or one ended
// within OnlineGrace. Calls only ring for online users. This is in memory,
// so it assumes one auth process; the stack runs one.

const (
	// PollWait is how long a poll is held open when there's nothing new.
	PollWait = 25 * time.Second
	// OnlineGrace: how long after a poll its user still counts as online
	// (the gap between polls, plus a slow network).
	OnlineGrace = 35 * time.Second
	queueLen    = 64
	idleDrop    = 10 * time.Minute
)

// Event is one thing that happened, for one user.
type Event struct {
	Seq  uint64 `json:"seq"`
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
}

// Event types.
const (
	EventCallRing   = "call.ring"
	EventCallUpdate = "call.update"
	EventFriends    = "friends"
	EventMissed     = "missed"
)

type inbox struct {
	seq      uint64
	events   []Event
	wake     chan struct{}
	polling  int
	lastPoll time.Time
}

// Hub holds every user's queue.
type Hub struct {
	epoch string
	now   func() time.Time
	mu    sync.Mutex
	users map[string]*inbox
}

func NewHub(now func() time.Time) *Hub {
	if now == nil {
		now = time.Now
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return &Hub{epoch: hex.EncodeToString(b), now: now, users: map[string]*inbox{}}
}

func (h *Hub) inboxLocked(userID string) *inbox {
	in := h.users[userID]
	if in == nil {
		in = &inbox{wake: make(chan struct{})}
		h.users[userID] = in
	}
	return in
}

// Publish queues an event for userID and wakes their polls.
func (h *Hub) Publish(userID, typ string, data any) {
	if userID == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	in := h.inboxLocked(userID)
	in.seq++
	in.events = append(in.events, Event{Seq: in.seq, Type: typ, Data: data})
	if len(in.events) > queueLen {
		in.events = append([]Event(nil), in.events[len(in.events)-queueLen:]...)
	}
	close(in.wake)
	in.wake = make(chan struct{})
}

// Online reports whether userID's app is polling.
func (h *Hub) Online(userID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	in := h.users[userID]
	return in != nil && (in.polling > 0 || h.now().Sub(in.lastPoll) < OnlineGrace)
}

func (h *Hub) cursor(seq uint64) string { return h.epoch + "." + strconv.FormatUint(seq, 10) }

// parseCursor returns the seq of a cursor from this epoch.
func (h *Hub) parseCursor(c string) (uint64, bool) {
	epoch, seq, ok := strings.Cut(c, ".")
	if !ok || epoch != h.epoch {
		return 0, false
	}
	n, err := strconv.ParseUint(seq, 10, 64)
	return n, err == nil
}

// Poll answers one long poll: the events after cursor, waiting up to wait
// for one. reset means the cursor was empty, from before a restart or too
// old: the caller sends the app a fresh snapshot (and Poll returns at once).
func (h *Hub) Poll(ctx context.Context, userID, cursor string, wait time.Duration) (events []Event, next string, reset bool) {
	h.mu.Lock()
	in := h.inboxLocked(userID)
	in.polling++
	in.lastPoll = h.now()
	after, ok := h.parseCursor(cursor)
	oldest := in.seq + 1
	if len(in.events) > 0 {
		oldest = in.events[0].Seq
	}
	if !ok || after > in.seq || after+1 < oldest {
		next = h.cursor(in.seq)
		h.doneLocked(in)
		h.mu.Unlock()
		return nil, next, true
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		if out := since(in.events, after); len(out) > 0 {
			next = h.cursor(in.seq)
			h.doneLocked(in)
			h.mu.Unlock()
			return out, next, false
		}
		wake := in.wake
		h.mu.Unlock()
		select {
		case <-wake:
			h.mu.Lock()
		case <-timer.C:
			h.mu.Lock()
			next = h.cursor(in.seq)
			h.doneLocked(in)
			h.mu.Unlock()
			return nil, next, false
		case <-ctx.Done():
			h.mu.Lock()
			next = h.cursor(in.seq)
			h.doneLocked(in)
			h.mu.Unlock()
			return nil, next, false
		}
	}
}

func (h *Hub) doneLocked(in *inbox) {
	in.polling--
	in.lastPoll = h.now()
}

func since(events []Event, after uint64) []Event {
	for i, e := range events {
		if e.Seq > after {
			return append([]Event(nil), events[i:]...)
		}
	}
	return nil
}

// Prune forgets users who stopped polling a while ago (their queued events
// go too; their next poll resets).
func (h *Hub) Prune() {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	for id, in := range h.users {
		if in.polling == 0 && now.Sub(in.lastPoll) > idleDrop {
			delete(h.users, id)
		}
	}
}

func (h *Hub) String() string { return fmt.Sprintf("hub(%s, %d users)", h.epoch, len(h.users)) }
