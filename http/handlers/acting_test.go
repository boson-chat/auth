package handlers

import (
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
)

func internalMux(cfg config.Config) *nethttp.ServeMux {
	h := &Handlers{Config: cfg}
	mux := nethttp.NewServeMux()
	h.RegisterInternal(mux, nil)
	return mux
}

// Without INTERNAL_ACTING_TOKEN the acting routes don't exist (a plain 404,
// which RoleServ reads as "no acting API").
func TestActingPrefixIsAbsentWithoutToken(t *testing.T) {
	var cfg config.Config
	cfg.InternalConfig.APIToken = "internal"
	mux := internalMux(cfg)
	for _, c := range []struct{ method, path string }{
		{"GET", "/internal/v1/acting/me"}, {"POST", "/internal/v1/acting/roles"},
		{"PATCH", "/internal/v1/acting/roles/rol_x"}, {"PUT", "/internal/v1/acting/users/usr_x/roles"},
	} {
		r := httptest.NewRequest(c.method, c.path, nil)
		r.Header.Set(InternalTokenHeader, "internal")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != nethttp.StatusNotFound {
			t.Errorf("%s %s: %d", c.method, c.path, w.Code)
		}
	}
}

// The acting routes accept only INTERNAL_ACTING_TOKEN (checked before any
// lookup, so no services are needed here).
func TestActingRejectsOtherTokens(t *testing.T) {
	var cfg config.Config
	cfg.InternalConfig.APIToken, cfg.InternalConfig.ActingToken = "internal", "acting"
	mux := internalMux(cfg)
	for _, tok := range []string{"", "internal", "actin", "acting "} {
		r := httptest.NewRequest("GET", "/internal/v1/acting/me", nil)
		r.Header.Set(InternalTokenHeader, tok)
		r.Header.Set(ActingAccountHeader, "alice")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != nethttp.StatusUnauthorized {
			t.Errorf("token %q: %d", tok, w.Code)
		}
	}
}

func TestIfMatch(t *testing.T) {
	want := time.Date(2026, 11, 13, 21, 4, 5, 123456000, time.UTC)
	for _, c := range []struct {
		hdr  string
		want *time.Time
		bad  bool
	}{
		{"", nil, false}, {"*", nil, false},
		{"2026-11-13T21:04:05.123456Z", &want, false},
		{`"2026-11-13T21:04:05.123456Z"`, &want, false},
		{`W/"2026-11-13T22:04:05.123456+01:00"`, &want, false},
		{"yesterday", nil, true},
	} {
		r := httptest.NewRequest("PATCH", "/v1/admin/roles/rol_x", nil)
		if c.hdr != "" {
			r.Header.Set("If-Match", c.hdr)
		}
		got, err := ifMatch(r)
		if (err != nil) != c.bad || (c.want == nil) != (got == nil) || (got != nil && !got.Equal(*c.want)) {
			t.Errorf("If-Match %q: %v, %v", c.hdr, got, err)
		}
	}
}
