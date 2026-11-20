package social

import (
	"testing"

	repo "github.com/boson-chat/auth/internal/db/repositories/social"
)

func TestDecideCall(t *testing.T) {
	friends := &repo.Relation{Friends: true}
	anytime := &repo.Relation{Friends: true, MineAnytime: true}
	stranger := &repo.Relation{}
	pv := func(calls string, dnd bool) *repo.Privacy {
		return &repo.Privacy{Calls: calls, DoNotDisturb: dnd, FriendRequests: repo.RequestsEveryone}
	}
	for name, c := range map[string]struct {
		rel  *repo.Relation
		pv   *repo.Privacy
		want CallOutcome
		why  string
	}{
		"friend, default":            {friends, repo.DefaultPrivacy("u"), Ring, ""},
		"stranger, default":          {stranger, repo.DefaultPrivacy("u"), Refused, ReasonFriendsOnly},
		"stranger, everyone":         {stranger, pv(repo.CallsEveryone, false), Ring, ""},
		"friend, nobody":             {friends, pv(repo.CallsNobody, false), Refused, ReasonCallsOff},
		"anytime, nobody":            {anytime, pv(repo.CallsNobody, false), Ring, ""},
		"friend, dnd":                {friends, pv(repo.CallsFriends, true), Missed, ""},
		"anytime, dnd":               {anytime, pv(repo.CallsFriends, true), Ring, ""},
		"stranger, everyone, dnd":    {stranger, pv(repo.CallsEveryone, true), Missed, ""},
		"callee blocked caller":      {&repo.Relation{IBlocked: true}, pv(repo.CallsEveryone, false), Silent, ""},
		"callee blocked friend-ish":  {&repo.Relation{IBlocked: true, Friends: true, MineAnytime: true}, pv(repo.CallsEveryone, false), Silent, ""},
		"caller blocked callee":      {&repo.Relation{TheyBlocked: true, Friends: true}, pv(repo.CallsEveryone, false), Refused, ReasonYouBlocked},
		"anytime without friendship": {&repo.Relation{MineAnytime: true}, pv(repo.CallsNobody, false), Refused, ReasonCallsOff},
		"unknown setting":            {stranger, pv("bogus", false), Refused, ReasonFriendsOnly},
	} {
		got, why := DecideCall(c.rel, c.pv)
		if got != c.want || why != c.why {
			t.Errorf("%s: got %v %q, want %v %q", name, got, why, c.want, c.why)
		}
	}
	if CallHint(&repo.Relation{IBlocked: true}, repo.DefaultPrivacy("u")) != "ok" {
		t.Error("a blocked caller must not be told")
	}
	if CallHint(friends, pv(repo.CallsFriends, true)) != "ok" {
		t.Error("Do not disturb isn't shown beforehand")
	}
}

func TestDecideRequest(t *testing.T) {
	every := repo.DefaultPrivacy("u")
	for name, c := range map[string]struct {
		rel  *repo.Relation
		pv   *repo.Privacy
		want RequestOutcome
		why  string
	}{
		"plain":                    {&repo.Relation{}, every, Send, ""},
		"friends already":          {&repo.Relation{Friends: true}, every, AlreadyFriends, ""},
		"they asked":               {&repo.Relation{Outgoing: true}, &repo.Privacy{FriendRequests: repo.RequestsNobody}, AcceptTheirs, ""},
		"recipient blocked sender": {&repo.Relation{IBlocked: true}, &repo.Privacy{FriendRequests: repo.RequestsNobody}, Hide, ""},
		"sender blocked recipient": {&repo.Relation{TheyBlocked: true}, every, Refuse, ReasonYouBlocked},
		"nobody":                   {&repo.Relation{}, &repo.Privacy{FriendRequests: repo.RequestsNobody}, Refuse, ReasonRequestsOff},
		"servers":                  {&repo.Relation{}, &repo.Privacy{FriendRequests: repo.RequestsServers}, CheckServers, ""},
	} {
		got, why := DecideRequest(c.rel, c.pv)
		if got != c.want || why != c.why {
			t.Errorf("%s: got %v %q, want %v %q", name, got, why, c.want, c.why)
		}
	}
}
