package social

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestShareChannel(t *testing.T) {
	chans := map[string][]string{"alice": {"#Boson", "#dev"}, "bob": {"#boson"}, "carol": {"#other"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Path != "/v1/whois" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		var req struct{ Nickname string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		list, ok := chans[req.Nickname]
		out := map[string]any{"success": true, "present": ok, "account": req.Nickname}
		var cs []map[string]string
		for _, c := range list {
			cs = append(cs, map[string]string{"name": c})
		}
		out["channels"] = cs
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	e := NewErgoChannels(srv.URL, "tok")
	ctx := context.Background()
	for pair, want := range map[[2]string]bool{
		{"alice", "bob"}: true, {"alice", "carol"}: false, {"dave", "bob"}: false,
	} {
		got, err := shareChannel(ctx, e, pair[0], pair[1])
		if err != nil || got != want {
			t.Errorf("%v: %v %v, want %v", pair, got, err, want)
		}
	}
	if _, err := shareChannel(ctx, NewErgoChannels(srv.URL, "wrong"), "alice", "bob"); err == nil {
		t.Error("bad token: no error")
	}
	if NewErgoChannels("", "tok") != nil {
		t.Error("no URL should be nil")
	}
	if ok, err := shareChannel(ctx, nil, "alice", "bob"); ok || err != nil {
		t.Error("nil Ergo shares nothing")
	}
}
