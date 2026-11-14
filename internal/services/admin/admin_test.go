package admin

import (
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
