package admin

import (
	"context"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"testing"
	"time"

	auditrepo "github.com/boson-chat/auth/internal/db/repositories/audit"
	"github.com/boson-chat/auth/internal/ids"
)

func TestCursorRoundTrip(t *testing.T) {
	c := auditrepo.Cursor{At: time.Date(2026, 11, 13, 10, 0, 0, 123456000, time.UTC), ID: ids.New(ids.Audit)}
	got, err := DecodeCursor(EncodeCursor(c))
	if err != nil {
		t.Fatal(err)
	}
	if !got.At.Equal(c.At) || got.ID != c.ID {
		t.Fatalf("round trip: %+v != %+v", got, c)
	}
	for _, bad := range []string{"", "!!!", EncodeCursor(auditrepo.Cursor{At: c.At, ID: "usr_x"}), "bm90LWEtY3Vyc29y"} {
		if _, err := DecodeCursor(bad); err == nil {
			t.Fatalf("DecodeCursor(%q) accepted", bad)
		}
	}
}

func TestListUsersRejectsUnknownSort(t *testing.T) {
	s := &AdminService{} // validation happens before the repository
	for _, sort := range []string{"bogus", "LAST_ACTIVE", "created_at"} {
		if _, _, err := s.ListUsers(t.Context(), "", sort, 10, 0); err == nil {
			t.Fatalf("sort %q accepted", sort)
		} else if e, ok := apperr.As(err); !ok || e.Code != "invalid_request" {
			t.Fatalf("sort %q: %v", sort, err)
		}
	}
}

type countsRepo struct {
	user.UserRepositoryImpl
	since []time.Time
}

func (c *countsRepo) Counts(_ context.Context, since ...time.Time) (int64, []int64, error) {
	c.since = since
	return 12, []int64{3, 7}, nil
}

func TestStatsAsksForTheLast7And30Days(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	repo := &countsRepo{}
	s := &AdminService{Users: repo, Now: func() time.Time { return now }}
	st, err := s.Stats(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if *st != (Stats{Accounts: 12, Active7d: 3, Active30d: 7}) {
		t.Fatalf("stats = %+v", st)
	}
	if len(repo.since) != 2 || !repo.since[0].Equal(now.AddDate(0, 0, -7)) || !repo.since[1].Equal(now.AddDate(0, 0, -30)) {
		t.Fatalf("since = %v", repo.since)
	}
}
