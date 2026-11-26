// Package ircaccounts serves the removed-accounts feed IRC polls
// (GET /internal/v1/irc/accounts/removed) to drop deleted and disabled
// accounts. The log itself is written by database triggers (migration 7).
package ircaccounts

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories/accountremoval"
)

const (
	DefaultLimit = 500
	MaxLimit     = 1000
	// Retention is how long log entries are kept; a poller that is offline
	// longer misses them.
	Retention = 180 * 24 * time.Hour
)

var (
	errCursor = apperr.Invalid("since is not a valid cursor")
	errLimit  = apperr.Invalid(fmt.Sprintf("limit must be an integer between 1 and %d", MaxLimit))
)

// Removal is one entry of the feed.
//
// Reason is what IRC does: "deleted" (erase the account) or "disabled"
// (disconnect its clients, keep the account). Federated accounts of a
// blocked home domain, and of a domain whose sessions an admin revoked,
// come as "disabled" too (the account isn't disabled in auth, but IRC
// treats them the same) with Cause saying why.
type Removal struct {
	Username string    `json:"username"`
	Reason   string    `json:"reason"`          // deleted | disabled
	Cause    string    `json:"cause,omitempty"` // "" | domain_blocked | sessions_revoked
	At       time.Time `json:"at"`
}

type IRCAccountsServiceImpl interface {
	// Removed returns the removals after cursor since ("" = from the
	// beginning) and the cursor to pass next time. Entries that no longer
	// apply are skipped (the cursor still moves past them): a deletion whose
	// username exists again (re-created account), and a disable whose user
	// was re-enabled or deleted since, a domain block that was lifted, and
	// a domain sessions revoke after which the user signed in again.
	Removed(ctx context.Context, since string, limit int) ([]Removal, string, error)
	// Cleanup prunes entries older than Retention.
	Cleanup(ctx context.Context) error
}

type IRCAccountsService struct {
	Removals accountremoval.AccountRemovalRepositoryImpl
	Now      func() time.Time
}

func NewIRCAccountsService(removals accountremoval.AccountRemovalRepositoryImpl, now func() time.Time) IRCAccountsServiceImpl {
	if now == nil {
		now = time.Now
	}
	return &IRCAccountsService{Removals: removals, Now: now}
}

// EncodeCursor renders a log position as "<txid>.<id>".
func EncodeCursor(p accountremoval.Position) string {
	return strconv.FormatUint(p.TxID, 10) + "." + strconv.FormatInt(p.ID, 10)
}

// DecodeCursor parses a cursor from EncodeCursor ("" = the start).
func DecodeCursor(s string) (accountremoval.Position, error) {
	if s == "" {
		return accountremoval.Position{}, nil
	}
	a, b, ok := strings.Cut(s, ".")
	if !ok {
		return accountremoval.Position{}, errCursor
	}
	txid, err1 := strconv.ParseUint(a, 10, 64)
	id, err2 := strconv.ParseInt(b, 10, 64)
	p := accountremoval.Position{TxID: txid, ID: id}
	if err1 != nil || err2 != nil || id < 0 || EncodeCursor(p) != s {
		return accountremoval.Position{}, errCursor
	}
	return p, nil
}

func (s *IRCAccountsService) Removed(ctx context.Context, since string, limit int) ([]Removal, string, error) {
	if limit < 1 || limit > MaxLimit {
		return nil, "", errLimit
	}
	pos, err := DecodeCursor(since)
	if err != nil {
		return nil, "", err
	}
	entries, err := s.Removals.After(ctx, pos, limit)
	if err != nil {
		return nil, "", err
	}
	out := []Removal{}
	next := since
	for _, e := range entries {
		next = EncodeCursor(e.Position)
		if !applies(e) {
			continue
		}
		r := Removal{Username: e.Username, Reason: e.Reason, At: e.At.UTC()}
		if e.Reason == accountremoval.ReasonDomainBlocked || e.Reason == accountremoval.ReasonSessionsRevoked {
			r.Reason, r.Cause = accountremoval.ReasonDisabled, e.Reason
		}
		out = append(out, r)
	}
	return out, next, nil
}

// applies reports whether IRC should still act on e.
func applies(e *accountremoval.Entry) bool {
	switch e.Reason {
	case accountremoval.ReasonDeleted:
		// Re-created under the same name: IRC must not wipe the new account.
		return !e.UsernameInUse
	case accountremoval.ReasonDisabled:
		// Re-enabled, or deleted (a later "deleted" entry covers it).
		return e.StillDisabled
	case accountremoval.ReasonDomainBlocked:
		// Unblocked since (or the account is gone).
		return e.StillDomainBlocked
	case accountremoval.ReasonSessionsRevoked:
		// Signed in again since: that new session must not be dropped.
		return e.NoLoginSince
	}
	return false
}

func (s *IRCAccountsService) Cleanup(ctx context.Context) error {
	_, err := s.Removals.DeleteBefore(ctx, s.Now().Add(-Retention))
	return err
}
