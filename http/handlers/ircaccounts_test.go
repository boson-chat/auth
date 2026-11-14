package handlers

import (
	"context"
	"encoding/json"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/services/ircaccounts"
)

type fakeIRCAccounts struct {
	since string
	limit int
	list  []ircaccounts.Removal
	next  string
}

func (f *fakeIRCAccounts) Removed(_ context.Context, since string, limit int) ([]ircaccounts.Removal, string, error) {
	f.since, f.limit = since, limit
	// The real service validates; mirror the limit check so the handler's
	// parsing is observable.
	if limit < 1 || limit > ircaccounts.MaxLimit {
		return nil, "", ircaccountsInvalidLimit()
	}
	return f.list, f.next, nil
}

func (f *fakeIRCAccounts) Cleanup(context.Context) error { return nil }

func ircaccountsInvalidLimit() error {
	_, _, err := ircaccounts.NewIRCAccountsService(nil, nil).Removed(context.Background(), "", 0)
	return err
}

func TestInternalRemovedAccounts(t *testing.T) {
	fake := &fakeIRCAccounts{}
	var cfg config.Config
	cfg.InternalConfig.APIToken = "secret"
	h := &Handlers{IRCAccounts: fake, Config: cfg}
	mux := nethttp.NewServeMux()
	h.RegisterInternal(mux, nil)
	get := func(query, token string) (int, map[string]any, string) {
		t.Helper()
		r := httptest.NewRequest("GET", "/internal/v1/irc/accounts/removed"+query, nil)
		if token != "" {
			r.Header.Set(InternalTokenHeader, token)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body, w.Body.String()
	}

	if code, _, _ := get("", ""); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _, _ := get("", "wrong"); code != 401 {
		t.Fatalf("wrong token: %d", code)
	}

	// Defaults; empty list renders as [].
	fake.list = []ircaccounts.Removal{}
	code, _, raw := get("", "secret")
	if code != 200 || fake.limit != ircaccounts.DefaultLimit || fake.since != "" ||
		strings.TrimSpace(raw) != `{"accounts":[],"next":""}` {
		t.Fatalf("defaults: %d limit=%d %s", code, fake.limit, raw)
	}

	fake.list = []ircaccounts.Removal{{Username: "alice", Reason: "deleted", At: time.Date(2026, 11, 14, 1, 2, 3, 0, time.UTC)}}
	fake.next = "740.12"
	code, _, raw = get("?since=739.4&limit=10", "secret")
	if code != 200 || fake.since != "739.4" || fake.limit != 10 ||
		strings.TrimSpace(raw) != `{"accounts":[{"username":"alice","reason":"deleted","at":"2026-11-14T01:02:03Z"}],"next":"740.12"}` {
		t.Fatalf("page: %d %+v %s", code, fake, raw)
	}

	for _, q := range []string{"?limit=0", "?limit=1001", "?limit=abc", "?limit=", "?limit=1.5"} {
		code, body, raw := get(q, "secret")
		if code != 400 || body["error"] != "invalid_request" || !strings.Contains(raw, "limit must be") {
			t.Errorf("%s: %d %s", q, code, raw)
		}
	}
}
