package social

import (
	repo "github.com/boson-chat/auth/internal/db/repositories/social"
)

// CallOutcome is what happens when someone calls.
type CallOutcome int

const (
	// Ring: the callee's open apps ring (or, with none open, a missed call).
	Ring CallOutcome = iota
	// Missed: Do not disturb. Counted as missed, never rings; the caller
	// sees "unavailable".
	Missed
	// Silent: the callee blocked the caller. Nothing reaches the callee;
	// the caller sees "unavailable", exactly as for Missed, and isn't told.
	Silent
	// Refused: the caller is told why (Reason) and nothing is recorded.
	Refused
)

// Refusal reasons (also the error codes and the relation's `call` field).
const (
	ReasonFriendsOnly = "friends_only"
	ReasonCallsOff    = "calls_off"
	ReasonYouBlocked  = "you_blocked"
)

// DecideCall applies the callee's settings to a call. rel is the relation
// as the callee sees the caller (rel.IBlocked: the callee blocked the
// caller; rel.TheyBlocked: the caller blocked the callee; rel.MineAnytime:
// the callee lets the caller call anytime).
func DecideCall(rel *repo.Relation, callee *repo.Privacy) (CallOutcome, string) {
	if rel.TheyBlocked {
		return Refused, ReasonYouBlocked
	}
	if rel.IBlocked {
		return Silent, ""
	}
	anytime := rel.Friends && rel.MineAnytime
	switch {
	case callee.Calls == repo.CallsNobody && !anytime:
		return Refused, ReasonCallsOff
	case callee.Calls == repo.CallsFriends && !rel.Friends:
		return Refused, ReasonFriendsOnly
	case callee.Calls != repo.CallsEveryone && callee.Calls != repo.CallsFriends && callee.Calls != repo.CallsNobody:
		// Unknown value: the default.
		if !rel.Friends {
			return Refused, ReasonFriendsOnly
		}
	}
	if callee.DoNotDisturb && !anytime {
		return Missed, ""
	}
	return Ring, ""
}

// CallHint is the relation's `call` field: what the caller's menu says
// before they call ("ok" or a refusal reason). Missed and Silent look "ok".
func CallHint(rel *repo.Relation, callee *repo.Privacy) string {
	if o, why := DecideCall(rel, callee); o == Refused {
		return why
	}
	return "ok"
}

// Friend request refusals.
const (
	ReasonRequestsOff         = "requests_off"
	ReasonRequestsServersOnly = "requests_servers_only"
)

// RequestOutcome is what happens to a friend request.
type RequestOutcome int

const (
	// Send: stored and shown to the recipient.
	Send RequestOutcome = iota
	// AcceptTheirs: they had already asked; now friends.
	AcceptTheirs
	// Hide: the recipient blocked the sender. Stored hidden; the sender
	// sees it as sent and isn't told.
	Hide
	// AlreadyFriends: nothing to do.
	AlreadyFriends
	// Refuse: the sender is told why.
	Refuse
	// CheckServers: allowed only when they share a channel (the caller
	// checks with Ergo, then sends or refuses with ReasonRequestsServersOnly).
	CheckServers
)

// DecideRequest applies the recipient's settings to a friend request. rel is
// the relation as the recipient sees the sender.
func DecideRequest(rel *repo.Relation, to *repo.Privacy) (RequestOutcome, string) {
	switch {
	case rel.Friends:
		return AlreadyFriends, ""
	case rel.TheyBlocked:
		return Refuse, ReasonYouBlocked
	case rel.IBlocked:
		return Hide, ""
	case rel.Outgoing:
		// The recipient had asked the sender: this is a yes.
		return AcceptTheirs, ""
	}
	switch to.FriendRequests {
	case repo.RequestsNobody:
		return Refuse, ReasonRequestsOff
	case repo.RequestsServers:
		return CheckServers, ""
	}
	return Send, ""
}
