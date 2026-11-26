package ircaccounts

import (
	"context"
	"testing"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories/accountremoval"
)

type memRepo struct {
	entries   []*accountremoval.Entry
	gotPos    accountremoval.Position
	gotLimit  int
	prunedAt  time.Time
	afterCall int
}

func (m *memRepo) After(_ context.Context, pos accountremoval.Position, limit int) ([]*accountremoval.Entry, error) {
	m.afterCall++
	m.gotPos, m.gotLimit = pos, limit
	var out []*accountremoval.Entry
	for _, e := range m.entries {
		if e.TxID > pos.TxID || (e.TxID == pos.TxID && e.ID > pos.ID) {
			out = append(out, e)
		}
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (m *memRepo) DeleteBefore(_ context.Context, t time.Time) (int64, error) {
	m.prunedAt = t
	return 0, nil
}

var at = time.Date(2026, 11, 14, 12, 0, 0, 0, time.FixedZone("x", 3600))

func entry(tx uint64, id int64, name, reason string, inUse, disabled bool) *accountremoval.Entry {
	return &accountremoval.Entry{Position: accountremoval.Position{TxID: tx, ID: id}, UserID: "usr_" + name,
		Username: name, Reason: reason, At: at, UsernameInUse: inUse, StillDisabled: disabled}
}

func TestCursorRoundTrip(t *testing.T) {
	for _, p := range []accountremoval.Position{{}, {TxID: 1, ID: 1}, {TxID: 1<<64 - 1, ID: 1<<63 - 1}, {TxID: 740, ID: 12}} {
		got, err := DecodeCursor(EncodeCursor(p))
		if err != nil || got != p {
			t.Fatalf("%+v: %+v %v", p, got, err)
		}
	}
	if EncodeCursor(accountremoval.Position{TxID: 740, ID: 12}) != "740.12" {
		t.Fatal("format")
	}
	if p, err := DecodeCursor(""); err != nil || p != (accountremoval.Position{}) {
		t.Fatalf("empty: %+v %v", p, err)
	}
	for _, bad := range []string{"x", "1", "1.", ".1", "1.2.3", "-1.2", "1.-2", "+1.2", "01.2", "1.02", " 1.2",
		"18446744073709551616.1", "1.9223372036854775808", "1,2"} {
		if _, err := DecodeCursor(bad); err == nil {
			t.Errorf("%q accepted", bad)
		} else if e, ok := apperr.As(err); !ok || e.Status != 400 || e.Code != "invalid_request" {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestRemovedFiltersAndAdvances(t *testing.T) {
	repo := &memRepo{entries: []*accountremoval.Entry{
		entry(10, 1, "alice", "deleted", false, false),
		entry(10, 2, "bob", "deleted", true, false),   // re-created: skipped
		entry(11, 3, "carl", "disabled", true, true),  // still disabled
		entry(12, 4, "dora", "disabled", true, false), // re-enabled: skipped
		entry(13, 5, "eve", "disabled", false, false), // deleted since: skipped
		entry(13, 6, "eve", "deleted", false, false),
	}}
	s := NewIRCAccountsService(repo, nil)
	got, next, err := s.Removed(t.Context(), "", 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Username != "alice" || got[0].Reason != "deleted" || got[1].Username != "carl" ||
		got[1].Reason != "disabled" || got[2].Username != "eve" || got[2].Reason != "deleted" || next != "13.6" {
		t.Fatalf("got %+v next %q", got, next)
	}
	if got[0].At.Location() != time.UTC || !got[0].At.Equal(at) {
		t.Fatalf("at must be UTC: %v", got[0].At)
	}
	// Paging: the cursor moves past filtered entries too.
	got, next, err = s.Removed(t.Context(), "", 2)
	if err != nil || len(got) != 1 || got[0].Username != "alice" || next != "10.2" {
		t.Fatalf("page 1: %+v %q %v", got, next, err)
	}
	got, next, err = s.Removed(t.Context(), next, 2)
	if err != nil || len(got) != 1 || got[0].Username != "carl" || next != "12.4" || repo.gotPos != (accountremoval.Position{TxID: 10, ID: 2}) {
		t.Fatalf("page 2: %+v %q %v", got, next, err)
	}
	// Nothing new: next echoes since and accounts is [], not nil.
	got, next, err = s.Removed(t.Context(), "13.6", 2)
	if err != nil || got == nil || len(got) != 0 || next != "13.6" {
		t.Fatalf("caught up: %#v %q %v", got, next, err)
	}
	repo.entries = nil
	if got, next, err = s.Removed(t.Context(), "", 2); err != nil || got == nil || next != "" {
		t.Fatalf("empty log: %#v %q %v", got, next, err)
	}
}

func TestRemovedValidation(t *testing.T) {
	repo := &memRepo{}
	s := NewIRCAccountsService(repo, nil)
	for _, c := range []struct {
		since string
		limit int
	}{{"", 0}, {"", -1}, {"", MaxLimit + 1}, {"garbage", 10}} {
		if _, _, err := s.Removed(t.Context(), c.since, c.limit); err == nil {
			t.Fatalf("%+v accepted", c)
		} else if e, ok := apperr.As(err); !ok || e.Status != 400 {
			t.Fatalf("%+v: %v", c, err)
		}
	}
	if repo.afterCall != 0 {
		t.Fatal("invalid request reached the repository")
	}
	for _, n := range []int{1, MaxLimit} {
		if _, _, err := s.Removed(t.Context(), "", n); err != nil || repo.gotLimit != n {
			t.Fatalf("limit %d: %v", n, err)
		}
	}
}

func TestCleanupRetention(t *testing.T) {
	repo := &memRepo{}
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	s := NewIRCAccountsService(repo, func() time.Time { return now })
	if err := s.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !repo.prunedAt.Equal(now.Add(-180 * 24 * time.Hour)) {
		t.Fatalf("pruned before %v", repo.prunedAt)
	}
}

// Domain blocks and domain session revokes reach IRC as "disabled" (the
// helper disconnects and keeps the account) with a cause, while they apply.
func TestRemovedFederatedDomainEntries(t *testing.T) {
	blocked := entry(20, 1, "fay", accountremoval.ReasonDomainBlocked, true, false)
	blocked.StillDomainBlocked = true
	unblocked := entry(20, 2, "gus", accountremoval.ReasonDomainBlocked, true, false) // domain unblocked since
	revoked := entry(21, 3, "hal", accountremoval.ReasonSessionsRevoked, true, false)
	revoked.NoLoginSince = true
	back := entry(21, 4, "ida", accountremoval.ReasonSessionsRevoked, true, false) // signed in again since
	banned := entry(22, 5, "jo", accountremoval.ReasonDisabled, true, true)
	banned.StillDomainBlocked = true // a ban's entry doesn't depend on the domain
	s := NewIRCAccountsService(&memRepo{entries: []*accountremoval.Entry{blocked, unblocked, revoked, back, banned}}, nil)
	got, next, err := s.Removed(t.Context(), "", 500)
	if err != nil {
		t.Fatal(err)
	}
	want := []Removal{
		{Username: "fay", Reason: "disabled", Cause: "domain_blocked"},
		{Username: "hal", Reason: "disabled", Cause: "sessions_revoked"},
		{Username: "jo", Reason: "disabled"},
	}
	if len(got) != len(want) || next != "22.5" {
		t.Fatalf("got %+v next %q", got, next)
	}
	for i, w := range want {
		if got[i].Username != w.Username || got[i].Reason != w.Reason || got[i].Cause != w.Cause {
			t.Fatalf("%d: got %+v want %+v", i, got[i], w)
		}
	}
}
