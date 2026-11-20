package integration

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/golang-jwt/jwt/v5"
)

// person is a signed-in test user.
type person struct {
	id, name, tok string
	cursor        string
}

func newSocialEnv(t *testing.T) *env {
	return newEnv(t, func(c *config.Config) {
		c.SocialConfig.EventsPollWait = 300 * time.Millisecond
	})
}

func (e *env) person(name string) *person {
	e.t.Helper()
	id := e.registerVerified(name, name+"@example.com")
	r := e.login(name, pw)
	e.expect(r, 200, "")
	return &person{id: id, name: name, tok: r.str("access_token")}
}

// poll is one GET /v1/events; the first (no cursor) resets with a snapshot.
func (e *env) poll(p *person) resp {
	e.t.Helper()
	r := e.api("GET", "/v1/events?cursor="+p.cursor, nil, bearer(p.tok))
	e.expect(r, 200, "")
	p.cursor = r.str("cursor")
	return r
}

// events returns the types (and data) of the events in a poll.
func events(r resp) ([]string, []map[string]any) {
	list, _ := r.body["events"].([]any)
	var types []string
	var data []map[string]any
	for _, x := range list {
		ev := x.(map[string]any)
		types = append(types, ev["type"].(string))
		d, _ := ev["data"].(map[string]any)
		data = append(data, d)
	}
	return types, data
}

func (e *env) befriend(a, b *person) {
	e.t.Helper()
	e.expect(e.api("POST", "/v1/friends/requests", map[string]string{"username": b.name}, bearer(a.tok)), 200, "")
	e.expect(e.api("POST", "/v1/friends/requests/"+a.id+"/accept", nil, bearer(b.tok)), 204, "")
}

func (e *env) relation(a, b *person) resp {
	e.t.Helper()
	r := e.api("GET", "/v1/users/"+b.name+"/relation", nil, bearer(a.tok))
	e.expect(r, 200, "")
	return r
}

func names(r resp, list string) []string {
	items, _ := r.body[list].([]any)
	var out []string
	for _, x := range items {
		out = append(out, x.(map[string]any)["username"].(string))
	}
	return out
}

func TestFriendRequests(t *testing.T) {
	e := newSocialEnv(t)
	alice, bob := e.person("alice"), e.person("bob")
	e.poll(bob)

	r := e.api("POST", "/v1/friends/requests", map[string]string{"username": "BOB"}, bearer(alice.tok))
	e.expect(r, 200, "")
	if r.str("relation") != "outgoing" || r.str("user", "user_id") != bob.id {
		t.Fatalf("request: %s", r.raw)
	}
	// Bob is told, sees it pending, and the relation reads "incoming".
	if types, _ := events(e.poll(bob)); len(types) != 1 || types[0] != "friends" {
		t.Fatalf("bob events %v", types)
	}
	fl := e.api("GET", "/v1/friends", nil, bearer(bob.tok))
	if got := names(fl, "incoming"); len(got) != 1 || got[0] != "alice" {
		t.Fatalf("bob incoming %v: %s", got, fl.raw)
	}
	if got := names(e.api("GET", "/v1/friends", nil, bearer(alice.tok)), "outgoing"); len(got) != 1 || got[0] != "bob" {
		t.Fatalf("alice outgoing %v", got)
	}
	if rel := e.relation(bob, alice); rel.str("relation") != "incoming" {
		t.Fatalf("relation %s", rel.raw)
	}
	e.expect(e.api("POST", "/v1/friends/requests/"+alice.id+"/accept", nil, bearer(bob.tok)), 204, "")
	for _, p := range []*person{alice, bob} {
		fl := e.api("GET", "/v1/friends", nil, bearer(p.tok))
		if len(names(fl, "friends")) != 1 || len(names(fl, "incoming"))+len(names(fl, "outgoing")) != 0 {
			t.Fatalf("%s after accept: %s", p.name, fl.raw)
		}
	}
	// Remove, then a request crossing an earlier one is a yes.
	e.expect(e.api("DELETE", "/v1/friends/"+alice.id, nil, bearer(bob.tok)), 204, "")
	e.expect(e.api("POST", "/v1/friends/requests", map[string]string{"username": "alice"}, bearer(bob.tok)), 200, "")
	r = e.api("POST", "/v1/friends/requests", map[string]string{"user_id": bob.id}, bearer(alice.tok))
	e.expect(r, 200, "")
	if r.str("relation") != "friend" {
		t.Fatalf("crossing request: %s", r.raw)
	}
	// Self, unknown.
	e.expect(e.api("POST", "/v1/friends/requests", map[string]string{"username": "alice"}, bearer(alice.tok)), 400, "invalid_request")
	e.expect(e.api("POST", "/v1/friends/requests", map[string]string{"username": "nobody"}, bearer(alice.tok)), 404, "user_not_found")

	// Who can send me friend requests.
	carol := e.person("carol")
	e.expect(e.api("PATCH", "/v1/me/privacy", map[string]string{"friend_requests": "nobody"}, bearer(carol.tok)), 200, "")
	e.expect(e.api("POST", "/v1/friends/requests", map[string]string{"username": "carol"}, bearer(alice.tok)), 403, "requests_off")
	// "People in my servers" without Ergo configured: nobody shares a channel.
	e.expect(e.api("PATCH", "/v1/me/privacy", map[string]string{"friend_requests": "servers"}, bearer(carol.tok)), 200, "")
	e.expect(e.api("POST", "/v1/friends/requests", map[string]string{"username": "carol"}, bearer(alice.tok)), 403, "requests_servers_only")
	e.expect(e.api("PATCH", "/v1/me/privacy", map[string]string{"friend_requests": "bogus"}, bearer(carol.tok)), 400, "invalid_request")
	// Decline / cancel.
	dave := e.person("dave")
	e.expect(e.api("POST", "/v1/friends/requests", map[string]string{"username": "dave"}, bearer(alice.tok)), 200, "")
	e.expect(e.api("DELETE", "/v1/friends/requests/"+alice.id, nil, bearer(dave.tok)), 204, "")
	e.expect(e.api("DELETE", "/v1/friends/requests/"+alice.id, nil, bearer(dave.tok)), 404, "not_found")
	e.expect(e.api("POST", "/v1/friends/requests", map[string]string{"username": "dave"}, bearer(alice.tok)), 200, "")
	e.expect(e.api("DELETE", "/v1/friends/requests/"+dave.id, nil, bearer(alice.tok)), 204, "")
	if got := names(e.api("GET", "/v1/friends", nil, bearer(dave.tok)), "incoming"); len(got) != 0 {
		t.Fatalf("cancelled request still shown: %v", got)
	}
}

func TestBlocking(t *testing.T) {
	e := newSocialEnv(t)
	alice, bob := e.person("alice"), e.person("bob")
	e.befriend(alice, bob)
	e.poll(bob)
	e.poll(alice)

	e.expect(e.api("POST", "/v1/blocks", map[string]string{"username": "alice"}, bearer(bob.tok)), 204, "")
	// Bob's lists: no friend, alice blocked. Alice isn't told anything.
	fl := e.api("GET", "/v1/friends", nil, bearer(bob.tok))
	if len(names(fl, "friends")) != 0 || len(names(fl, "blocked")) != 1 {
		t.Fatalf("bob after block: %s", fl.raw)
	}
	if types, _ := events(e.poll(alice)); len(types) != 0 {
		t.Fatalf("alice was told: %v", types)
	}
	e.poll(bob)
	// Her request is stored hidden: she sees it sent, he never sees it.
	r := e.api("POST", "/v1/friends/requests", map[string]string{"username": "bob"}, bearer(alice.tok))
	e.expect(r, 200, "")
	if r.str("relation") != "outgoing" {
		t.Fatalf("hidden request: %s", r.raw)
	}
	if got := names(e.api("GET", "/v1/friends", nil, bearer(bob.tok)), "incoming"); len(got) != 0 {
		t.Fatalf("bob sees a blocked request: %v", got)
	}
	// Her call: looks fine beforehand, comes back unavailable, never rings
	// and isn't a missed call.
	if rel := e.relation(alice, bob); rel.str("call") != "ok" {
		t.Fatalf("relation tells alice: %s", rel.raw)
	}
	r = e.api("POST", "/v1/calls", map[string]any{"username": "bob"}, bearer(alice.tok))
	e.expect(r, 201, "")
	if r.str("call", "state") != "unavailable" {
		t.Fatalf("blocked call: %s", r.raw)
	}
	if types, _ := events(e.poll(bob)); len(types) != 0 {
		t.Fatalf("bob got %v", types)
	}
	if m := e.api("GET", "/v1/calls/missed", nil, bearer(bob.tok)); m.body["count"].(float64) != 0 {
		t.Fatalf("missed %s", m.raw)
	}
	// Bob can't call someone he blocked, and is told.
	e.expect(e.api("POST", "/v1/calls", map[string]any{"username": "alice"}, bearer(bob.tok)), 403, "you_blocked")
	if rel := e.relation(bob, alice); rel.str("relation") != "blocked" || rel.str("call") != "you_blocked" {
		t.Fatalf("bob's view: %s", rel.raw)
	}
	e.expect(e.api("DELETE", "/v1/blocks/"+alice.id, nil, bearer(bob.tok)), 204, "")
	if rel := e.relation(bob, alice); rel.str("relation") != "none" {
		t.Fatalf("after unblock: %s", rel.raw)
	}
}

func TestCallPolicy(t *testing.T) {
	e := newSocialEnv(t)
	alice, bob, carol := e.person("alice"), e.person("bob"), e.person("carol")
	e.befriend(alice, bob)
	e.poll(bob)

	// Default: friends only.
	if rel := e.relation(carol, bob); rel.str("call") != "friends_only" {
		t.Fatalf("relation %s", rel.raw)
	}
	r := e.api("POST", "/v1/calls", map[string]any{"username": "bob"}, bearer(carol.tok))
	e.expect(r, 403, "friends_only")
	if !strings.Contains(r.str("message"), "bob only takes calls from friends") {
		t.Fatalf("message %s", r.raw)
	}
	// Everyone.
	e.expect(e.api("PATCH", "/v1/me/privacy", map[string]string{"calls": "everyone"}, bearer(bob.tok)), 200, "")
	if rel := e.relation(carol, bob); rel.str("call") != "ok" {
		t.Fatalf("everyone: %s", rel.raw)
	}
	// Nobody: even friends, unless they may call anytime.
	e.expect(e.api("PATCH", "/v1/me/privacy", map[string]string{"calls": "nobody"}, bearer(bob.tok)), 200, "")
	e.expect(e.api("POST", "/v1/calls", map[string]any{"username": "bob"}, bearer(alice.tok)), 403, "calls_off")
	e.expect(e.api("PATCH", "/v1/friends/"+alice.id, map[string]bool{"can_call_anytime": true}, bearer(bob.tok)), 204, "")
	if rel := e.relation(alice, bob); rel.str("call") != "ok" {
		t.Fatalf("anytime through nobody: %s", rel.raw)
	}
	if rel := e.relation(bob, alice); !rel.body["can_call_anytime"].(bool) {
		t.Fatalf("bob's switch: %s", rel.raw)
	}
	// Internal check.
	r = e.do(e.internal, "GET", "/internal/v1/calls/check?from="+carol.id+"&to="+bob.id, nil, header("X-Internal-Token", e.cfg.InternalConfig.APIToken))
	e.expect(r, 200, "")
	if r.str("result") != "calls_off" {
		t.Fatalf("internal check %s", r.raw)
	}
	r = e.do(e.internal, "GET", "/internal/v1/calls/check?from="+alice.id+"&to="+bob.id, nil, header("X-Internal-Token", e.cfg.InternalConfig.APIToken))
	if r.str("result") != "ok" {
		t.Fatalf("internal check anytime %s", r.raw)
	}
	e.expect(e.do(e.internal, "GET", "/internal/v1/calls/check?from=a&to=b", nil), 401, "")
}

func TestCallRingAcceptEnd(t *testing.T) {
	e := newSocialEnv(t)
	alice, bob := e.person("alice"), e.person("bob")
	e.befriend(alice, bob)
	// Bob's app is open (polling); alice's too.
	if snap := e.poll(bob); snap.body["reset"] != true || snap.body["snapshot"] == nil {
		t.Fatalf("first poll: %s", snap.raw)
	}
	e.poll(alice)

	r := e.api("POST", "/v1/calls", map[string]any{"username": "bob", "video": true}, bearer(alice.tok))
	e.expect(r, 201, "")
	id := r.str("call", "id")
	if r.str("call", "state") != "ringing" || r.str("call", "direction") != "outgoing" || r.str("call", "room") != "call:"+id {
		t.Fatalf("start: %s", r.raw)
	}
	types, data := events(e.poll(bob))
	if len(types) != 1 || types[0] != "call.ring" || data[0]["id"] != id || data[0]["video"] != true {
		t.Fatalf("bob events %v %v", types, data)
	}
	if peer := data[0]["peer"].(map[string]any); peer["username"] != "alice" || data[0]["direction"] != "incoming" {
		t.Fatalf("ring %v", data[0])
	}
	// An app opening now still rings: the snapshot lists the call.
	if snap := e.api("GET", "/v1/events", nil, bearer(bob.tok)); len(snap.body["snapshot"].(map[string]any)["ringing"].([]any)) != 1 {
		t.Fatalf("snapshot %s", snap.raw)
	}
	// Only the callee answers.
	e.expect(e.api("POST", "/v1/calls/"+id+"/accept", nil, bearer(alice.tok)), 404, "not_found")
	r = e.api("POST", "/v1/calls/"+id+"/accept", nil, bearer(bob.tok))
	e.expect(r, 200, "")
	if r.str("call", "state") != "answered" || r.str("voice", "room") != "call:"+id {
		t.Fatalf("accept: %s", r.raw)
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(r.str("voice", "token"), claims, e.jwksKeyfunc(), jwt.WithAudience("quicvoice")); err != nil {
		t.Fatal(err)
	}
	if rooms := claims["rooms"].([]any); len(rooms) != 1 || rooms[0] != "call:"+id || claims["sub"] != bob.id {
		t.Fatalf("voice claims %v", claims)
	}
	if types, data := events(e.poll(alice)); len(types) != 1 || types[0] != "call.update" || data[0]["state"] != "answered" {
		t.Fatalf("alice events %v %v", types, data)
	}
	// The caller gets her token; a stranger can't.
	r = e.api("POST", "/v1/calls/"+id+"/token", nil, bearer(alice.tok))
	e.expect(r, 200, "")
	carol := e.person("carol")
	e.expect(e.api("POST", "/v1/calls/"+id+"/token", nil, bearer(carol.tok)), 404, "not_found")
	// Nobody gets a call room through the plain voice token endpoint.
	e.expect(e.api("POST", "/v1/voice/token", map[string]any{"rooms": []string{"call:" + id}}, bearer(carol.tok)), 400, "invalid_request")
	e.expect(e.api("POST", "/v1/voice/guest-token", map[string]any{"nick": "Wanderer", "guest_id": guestID, "rooms": []string{"call:" + id}}), 403, "")

	e.expect(e.api("POST", "/v1/calls/"+id+"/end", nil, bearer(bob.tok)), 200, "")
	if types, data := events(e.poll(alice)); len(types) != 1 || data[0]["state"] != "ended" {
		t.Fatalf("end %v %v", types, data)
	}
	e.expect(e.api("POST", "/v1/calls/"+id+"/token", nil, bearer(alice.tok)), 409, "call_over")
	e.expect(e.api("POST", "/v1/calls/"+id+"/end", nil, bearer(alice.tok)), 409, "call_over")
}

func TestCallDeclineMissedDND(t *testing.T) {
	e := newSocialEnv(t)
	alice, bob := e.person("alice"), e.person("bob")
	e.befriend(alice, bob)
	e.poll(bob)
	e.poll(alice)

	// Decline: the caller sees declined ("busy").
	id := e.api("POST", "/v1/calls", map[string]any{"username": "bob"}, bearer(alice.tok)).str("call", "id")
	e.poll(bob)
	e.expect(e.api("POST", "/v1/calls/"+id+"/decline", nil, bearer(bob.tok)), 200, "")
	if _, data := events(e.poll(alice)); len(data) != 1 || data[0]["state"] != "declined" {
		t.Fatalf("decline %v", data)
	}

	// Unanswered for 45 s: missed for both, counted for bob.
	id = e.api("POST", "/v1/calls", map[string]any{"username": "bob"}, bearer(alice.tok)).str("call", "id")
	e.poll(bob)
	e.ageCall(id, time.Minute)
	e.app.Social.Sweep(context.Background())
	types, data := events(e.poll(bob))
	if len(types) != 2 || types[0] != "call.update" || data[0]["state"] != "missed" || types[1] != "missed" || data[1]["count"] != 1.0 {
		t.Fatalf("missed %v %v", types, data)
	}
	if _, data := events(e.poll(alice)); len(data) != 1 || data[0]["state"] != "missed" {
		t.Fatalf("caller after timeout %v", data)
	}

	// Cancel while ringing: a missed call too.
	id = e.api("POST", "/v1/calls", map[string]any{"username": "bob"}, bearer(alice.tok)).str("call", "id")
	e.expect(e.api("POST", "/v1/calls/"+id+"/cancel", nil, bearer(bob.tok)), 404, "not_found")
	e.expect(e.api("POST", "/v1/calls/"+id+"/cancel", nil, bearer(alice.tok)), 200, "")
	m := e.api("GET", "/v1/calls/missed", nil, bearer(bob.tok))
	if m.body["count"] != 2.0 || len(m.body["calls"].([]any)) != 2 {
		t.Fatalf("missed list %s", m.raw)
	}

	// Do not disturb: never rings, counted, the caller sees unavailable.
	e.poll(bob)
	e.expect(e.api("PATCH", "/v1/me/privacy", map[string]bool{"do_not_disturb": true}, bearer(bob.tok)), 200, "")
	r := e.api("POST", "/v1/calls", map[string]any{"username": "bob"}, bearer(alice.tok))
	if r.str("call", "state") != "unavailable" {
		t.Fatalf("dnd: %s", r.raw)
	}
	types, _ = events(e.poll(bob))
	if len(types) != 1 || types[0] != "missed" {
		t.Fatalf("dnd events %v", types)
	}
	// ...except a friend who may call anytime.
	e.expect(e.api("PATCH", "/v1/friends/"+alice.id, map[string]bool{"can_call_anytime": true}, bearer(bob.tok)), 204, "")
	if r := e.api("POST", "/v1/calls", map[string]any{"username": "bob"}, bearer(alice.tok)); r.str("call", "state") != "ringing" {
		t.Fatalf("anytime through dnd: %s", r.raw)
	}
	// Seen: the count goes to 0 on every app.
	e.poll(bob)
	e.expect(e.api("POST", "/v1/calls/missed/seen", nil, bearer(bob.tok)), 204, "")
	if _, data := events(e.poll(bob)); len(data) != 1 || data[0]["count"] != 0.0 {
		t.Fatalf("seen %v", data)
	}
}

func TestCallOffline(t *testing.T) {
	e := newSocialEnv(t)
	alice, bob := e.person("alice"), e.person("bob")
	e.befriend(alice, bob)
	// Bob's app isn't open: nothing rings, it's a missed call he sees next time.
	r := e.api("POST", "/v1/calls", map[string]any{"username": "bob"}, bearer(alice.tok))
	if r.str("call", "state") != "unavailable" {
		t.Fatalf("offline: %s", r.raw)
	}
	snap := e.poll(bob).body["snapshot"].(map[string]any)
	if snap["missed"] != 1.0 || len(snap["ringing"].([]any)) != 0 {
		t.Fatalf("snapshot %v", snap)
	}
}

// ageCall moves a call's start back by d.
func (e *env) ageCall(id string, d time.Duration) {
	e.t.Helper()
	sqlDB, err := sql.Open("pgx", e.cfg.DBConfig.URL)
	if err != nil {
		e.t.Fatal(err)
	}
	defer sqlDB.Close()
	if _, err := sqlDB.Exec("UPDATE calls SET created_at = created_at - $1::interval WHERE id = $2", d.String(), id); err != nil {
		e.t.Fatal(err)
	}
}
