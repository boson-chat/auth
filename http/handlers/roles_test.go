package handlers

import (
	nethttp "net/http"
	"net/http/httptest"
	"testing"
)

func TestNotModified(t *testing.T) {
	for _, c := range []struct {
		inm  string
		want bool
	}{
		{"", false}, {`"abc"`, true}, {`W/"abc"`, true}, {`"x", "abc"`, true}, {"*", true}, {`"abcd"`, false}, {"abc", false},
	} {
		r := httptest.NewRequest(nethttp.MethodGet, "/v1/roles", nil)
		if c.inm != "" {
			r.Header.Set("If-None-Match", c.inm)
		}
		w := httptest.NewRecorder()
		if got := notModified(w, r, "abc"); got != c.want {
			t.Errorf("If-None-Match %q: %v, want %v", c.inm, got, c.want)
		}
		if w.Header().Get("ETag") != `"abc"` {
			t.Errorf("ETag = %q", w.Header().Get("ETag"))
		}
		if c.want && w.Code != nethttp.StatusNotModified {
			t.Errorf("status %d", w.Code)
		}
	}
}
