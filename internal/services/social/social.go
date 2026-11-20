// Package social is friends, blocks, privacy settings and private 1:1
// calls (docs/friends-calls.md): the policy for who may call or friend
// whom, the calls' state, and the event feed that rings open apps.
package social

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	repo "github.com/boson-chat/auth/internal/db/repositories/social"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/services/authn"
)

const (
	// RingTimeout: an unanswered call becomes a missed call.
	RingTimeout = 45 * time.Second
	// staleCall: an answered call nobody ended (both apps died) is closed.
	staleCall = 12 * time.Hour
	// keepCalls: finished calls are deleted after this.
	keepCalls = 30 * 24 * time.Hour
	// missedListLimit: how many missed calls GET /v1/calls/missed lists.
	missedListLimit = 50
	// CallRoomPrefix starts the voice room of a call (quicvoice's private
	// call rooms).
	CallRoomPrefix = "call:"
)

var (
	ErrUserNotFound   = apperr.New(http.StatusNotFound, "user_not_found", "no user with that name")
	ErrSelf           = apperr.New(http.StatusBadRequest, "invalid_request", "that's you")
	ErrNotFriends     = apperr.New(http.StatusNotFound, "not_found", "not a friend")
	ErrNoRequest      = apperr.New(http.StatusNotFound, "not_found", "no such friend request")
	ErrCallNotFound   = apperr.New(http.StatusNotFound, "not_found", "no such call")
	ErrCallOver       = apperr.New(http.StatusConflict, "call_over", "the call is no longer ringing or in progress")
	ErrInvalidSetting = apperr.New(http.StatusBadRequest, "invalid_request", "unknown setting value")
)

// refusal is the error for a refused call or friend request.
func refusal(reason, name string) error {
	switch reason {
	case ReasonFriendsOnly:
		return apperr.New(http.StatusForbidden, reason, name+" only takes calls from friends")
	case ReasonCallsOff:
		return apperr.New(http.StatusForbidden, reason, name+" isn't taking calls")
	case ReasonYouBlocked:
		return apperr.New(http.StatusForbidden, reason, "you blocked "+name+"; unblock them first")
	case ReasonRequestsOff:
		return apperr.New(http.StatusForbidden, reason, name+" isn't taking friend requests")
	case ReasonRequestsServersOnly:
		return apperr.New(http.StatusForbidden, reason, name+" only takes friend requests from people in their servers")
	}
	return apperr.ErrForbidden
}

// Person is a user as the API shows them.
type Person struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

// Friend is a friends-list entry.
type Friend struct {
	Person
	// CanCallAnytime: my switch for them (they ring through DND / Nobody).
	CanCallAnytime bool      `json:"can_call_anytime"`
	Since          time.Time `json:"since"`
}

// FriendsList is GET /v1/friends.
type FriendsList struct {
	Friends  []Friend `json:"friends"`
	Incoming []Friend `json:"incoming"`
	Outgoing []Friend `json:"outgoing"`
	Blocked  []Friend `json:"blocked"`
}

// RelationView is GET /v1/users/{username}/relation.
type RelationView struct {
	User Person `json:"user"`
	// friend | incoming | outgoing | blocked | none
	Relation       string `json:"relation"`
	CanCallAnytime bool   `json:"can_call_anytime"`
	// ok | friends_only | calls_off | you_blocked
	Call string `json:"call"`
}

// Privacy is GET/PATCH /v1/me/privacy.
type Privacy struct {
	// nobody | friends | everyone
	Calls        string `json:"calls"`
	DoNotDisturb bool   `json:"do_not_disturb"`
	// nobody | servers | everyone
	FriendRequests string `json:"friend_requests"`
}

// PrivacyPatch is a PATCH body: nil fields stay.
type PrivacyPatch struct {
	Calls          *string `json:"calls"`
	DoNotDisturb   *bool   `json:"do_not_disturb"`
	FriendRequests *string `json:"friend_requests"`
}

// CallView is a call as one of its two people sees it.
type CallView struct {
	ID string `json:"id"`
	// The voice (and video) room: quicvoice's private call room.
	Room  string `json:"room"`
	Video bool   `json:"video"`
	// ringing | answered | declined | missed | ended | unavailable
	State string `json:"state"`
	// outgoing (I called) | incoming
	Direction string    `json:"direction"`
	Peer      Person    `json:"peer"`
	CreatedAt time.Time `json:"created_at"`
	// When it stops ringing.
	ExpiresAt time.Time `json:"expires_at"`
}

// VoiceGrant is a voice token for a call's room.
type VoiceGrant struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
	Room      string `json:"room"`
}

// MissedList is GET /v1/calls/missed.
type MissedList struct {
	Count int64      `json:"count"`
	Calls []CallView `json:"calls"`
}

// Snapshot is sent with a poll that resets: what an app needs to show
// without waiting for events.
type Snapshot struct {
	// Calls ringing for me right now.
	Ringing []CallView `json:"ringing"`
	Missed  int64      `json:"missed"`
	// Visible friend requests waiting for me.
	PendingRequests int `json:"pending_requests"`
}

// PollResult is GET /v1/events.
type PollResult struct {
	Cursor   string    `json:"cursor"`
	Events   []Event   `json:"events"`
	Reset    bool      `json:"reset"`
	Snapshot *Snapshot `json:"snapshot,omitempty"`
}

// CallTokenMinter mints a voice token for a private call's room (authn).
type CallTokenMinter func(ctx context.Context, p *authn.Principal, room string) (string, time.Time, error)

type Deps struct {
	Repo  repo.SocialRepositoryImpl
	Users user.UserRepositoryImpl
	Tx    db.TxManagerImpl
	Hub   *Hub
	// Ergo: shared channels for "People in my servers" (nil: none).
	Ergo      ErgoChannels
	MintToken CallTokenMinter
	Now       func() time.Time
	// PollWait overrides PollWait (tests).
	PollWait time.Duration
}

type SocialServiceImpl interface {
	Friends(ctx context.Context, me string) (*FriendsList, error)
	Relation(ctx context.Context, me, username string) (*RelationView, error)
	// RequestFriend sends (or accepts) a friend request to a username or user id.
	RequestFriend(ctx context.Context, me *user.User, target string) (*RelationView, error)
	AcceptRequest(ctx context.Context, me, from string) error
	// DeleteRequest declines their request or cancels mine.
	DeleteRequest(ctx context.Context, me, other string) error
	RemoveFriend(ctx context.Context, me, other string) error
	SetAnytime(ctx context.Context, me, friend string, on bool) error
	Block(ctx context.Context, me, target string) error
	Unblock(ctx context.Context, me, other string) error

	Privacy(ctx context.Context, me string) (*Privacy, error)
	UpdatePrivacy(ctx context.Context, me string, p PrivacyPatch) (*Privacy, error)
	// CanCall is the internal "may caller ring callee?" check: ok, or a
	// refusal reason; "unavailable" for a block or Do not disturb.
	CanCall(ctx context.Context, callerID, calleeID string) (string, error)

	StartCall(ctx context.Context, p *authn.Principal, target string, video bool) (*CallView, error)
	AcceptCall(ctx context.Context, p *authn.Principal, id string) (*CallView, *VoiceGrant, error)
	DeclineCall(ctx context.Context, me, id string) (*CallView, error)
	CancelCall(ctx context.Context, me, id string) (*CallView, error)
	EndCall(ctx context.Context, me, id string) (*CallView, error)
	CallToken(ctx context.Context, p *authn.Principal, id string) (*VoiceGrant, error)
	Missed(ctx context.Context, me string) (*MissedList, error)
	MarkMissedSeen(ctx context.Context, me string) error

	Poll(ctx context.Context, me, cursor string) (*PollResult, error)
	// Sweep turns calls unanswered for RingTimeout into missed calls.
	Sweep(ctx context.Context)
	// Run sweeps every second and cleans up until ctx is done.
	Run(ctx context.Context)
}

type SocialService struct {
	Deps
}

func NewSocialService(d Deps) SocialServiceImpl {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Hub == nil {
		d.Hub = NewHub(d.Now)
	}
	if d.PollWait <= 0 {
		d.PollWait = PollWait
	}
	return &SocialService{Deps: d}
}

func person(u *user.User) Person {
	return Person{UserID: u.ID, Username: u.Username, DisplayName: u.DisplayName}
}

// find resolves a username (or usr_ id) to an enabled user other than me.
func (s *SocialService) find(ctx context.Context, me, target string) (*user.User, error) {
	target = strings.TrimSpace(target)
	if target == "" || len(target) > 64 {
		return nil, ErrUserNotFound
	}
	var u *user.User
	var err error
	if ids.HasPrefix(target, ids.User) {
		u, err = s.Users.FindByID(ctx, target)
	} else {
		u, err = s.Users.FindByUsernameFolded(ctx, nick.Fold(strings.TrimPrefix(target, "@")))
	}
	if errors.Is(err, repositories.ErrNotFound) || (err == nil && u.Disabled()) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	if u.ID == me {
		return nil, ErrSelf
	}
	return u, nil
}

// findID is find for a user id from a URL (disabled users are fine: you
// can still unblock or unfriend them).
func (s *SocialService) findID(ctx context.Context, me, id string) (*user.User, error) {
	if !ids.HasPrefix(id, ids.User) {
		return nil, ErrUserNotFound
	}
	u, err := s.Users.FindByID(ctx, id)
	if errors.Is(err, repositories.ErrNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	if u.ID == me {
		return nil, ErrSelf
	}
	return u, nil
}

func friendsOf(list []*repo.Person) []Friend {
	out := make([]Friend, 0, len(list))
	for _, p := range list {
		out = append(out, Friend{Person: Person{UserID: p.UserID, Username: p.Username, DisplayName: p.DisplayName},
			CanCallAnytime: p.CanCallAnytime, Since: p.Since})
	}
	return out
}

func (s *SocialService) Friends(ctx context.Context, me string) (*FriendsList, error) {
	friends, err := s.Repo.Friends(ctx, me)
	if err != nil {
		return nil, err
	}
	in, err := s.Repo.IncomingRequests(ctx, me)
	if err != nil {
		return nil, err
	}
	out, err := s.Repo.OutgoingRequests(ctx, me)
	if err != nil {
		return nil, err
	}
	blocked, err := s.Repo.Blocked(ctx, me)
	if err != nil {
		return nil, err
	}
	return &FriendsList{Friends: friendsOf(friends), Incoming: friendsOf(in), Outgoing: friendsOf(out), Blocked: friendsOf(blocked)}, nil
}

func relationName(r *repo.Relation) string {
	switch {
	case r.IBlocked:
		return "blocked"
	case r.Friends:
		return "friend"
	case r.Incoming:
		return "incoming"
	case r.Outgoing:
		return "outgoing"
	}
	return "none"
}

func (s *SocialService) relationView(ctx context.Context, me string, other *user.User) (*RelationView, error) {
	mine, err := s.Repo.Relation(ctx, me, other.ID)
	if err != nil {
		return nil, err
	}
	// The call hint is decided on the other's side: their settings, their view of me.
	theirs, err := s.Repo.Relation(ctx, other.ID, me)
	if err != nil {
		return nil, err
	}
	pv, err := s.Repo.Privacy(ctx, other.ID)
	if err != nil {
		return nil, err
	}
	return &RelationView{User: person(other), Relation: relationName(mine), CanCallAnytime: mine.Friends && mine.MineAnytime,
		Call: CallHint(theirs, pv)}, nil
}

func (s *SocialService) Relation(ctx context.Context, me, username string) (*RelationView, error) {
	u, err := s.find(ctx, me, username)
	if err != nil {
		return nil, err
	}
	return s.relationView(ctx, me, u)
}

func (s *SocialService) changed(userIDs ...string) {
	for _, id := range userIDs {
		s.Hub.Publish(id, EventFriends, nil)
	}
}

func (s *SocialService) RequestFriend(ctx context.Context, me *user.User, target string) (*RelationView, error) {
	to, err := s.find(ctx, me.ID, target)
	if err != nil {
		return nil, err
	}
	rel, err := s.Repo.Relation(ctx, to.ID, me.ID)
	if err != nil {
		return nil, err
	}
	pv, err := s.Repo.Privacy(ctx, to.ID)
	if err != nil {
		return nil, err
	}
	now := s.Now()
	outcome, why := DecideRequest(rel, pv)
	if outcome == CheckServers {
		ok, err := shareChannel(ctx, s.Ergo, me.Username, to.Username)
		if err != nil {
			logger.FromCtx(ctx).Warn().Err(err).Msg("friend request: shared channel check")
		}
		outcome, why = Send, ""
		if !ok {
			outcome, why = Refuse, ReasonRequestsServersOnly
		}
	}
	switch outcome {
	case Refuse:
		return nil, refusal(why, to.Username)
	case AcceptTheirs:
		if err := s.Repo.AddFriends(ctx, me.ID, to.ID, now); err != nil {
			return nil, err
		}
		s.changed(me.ID, to.ID)
	case Hide:
		if err := s.Repo.PutRequest(ctx, &repo.Request{FromID: me.ID, ToID: to.ID, Hidden: true, CreatedAt: now}); err != nil {
			return nil, err
		}
		s.changed(me.ID)
	case Send:
		if err := s.Repo.PutRequest(ctx, &repo.Request{FromID: me.ID, ToID: to.ID, CreatedAt: now}); err != nil {
			return nil, err
		}
		s.changed(me.ID, to.ID)
	}
	return s.relationView(ctx, me.ID, to)
}

func (s *SocialService) AcceptRequest(ctx context.Context, me, from string) error {
	u, err := s.findID(ctx, me, from)
	if err != nil {
		return err
	}
	rel, err := s.Repo.Relation(ctx, me, u.ID)
	if err != nil {
		return err
	}
	if !rel.Incoming {
		return ErrNoRequest
	}
	if err := s.Repo.AddFriends(ctx, me, u.ID, s.Now()); err != nil {
		return err
	}
	s.changed(me, u.ID)
	return nil
}

func (s *SocialService) DeleteRequest(ctx context.Context, me, other string) error {
	u, err := s.findID(ctx, me, other)
	if err != nil {
		return err
	}
	rel, err := s.Repo.Relation(ctx, me, u.ID)
	if err != nil {
		return err
	}
	found := false
	if rel.Outgoing {
		if found, err = s.Repo.DeleteRequest(ctx, me, u.ID); err != nil {
			return err
		}
	}
	// Only a request I can see (declining a hidden one would tell them).
	if rel.Incoming {
		ok, err := s.Repo.DeleteRequest(ctx, u.ID, me)
		if err != nil {
			return err
		}
		found = found || ok
	}
	if !found {
		return ErrNoRequest
	}
	s.changed(me, u.ID)
	return nil
}

func (s *SocialService) RemoveFriend(ctx context.Context, me, other string) error {
	u, err := s.findID(ctx, me, other)
	if err != nil {
		return err
	}
	ok, err := s.Repo.RemoveFriends(ctx, me, u.ID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFriends
	}
	s.changed(me, u.ID)
	return nil
}

func (s *SocialService) SetAnytime(ctx context.Context, me, friend string, on bool) error {
	u, err := s.findID(ctx, me, friend)
	if err != nil {
		return err
	}
	ok, err := s.Repo.SetAnytime(ctx, me, u.ID, on)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFriends
	}
	s.changed(me)
	return nil
}

func (s *SocialService) Block(ctx context.Context, me, target string) error {
	u, err := s.find(ctx, me, target)
	if err != nil {
		return err
	}
	if err := s.Repo.Block(ctx, me, u.ID, s.Now()); err != nil {
		return err
	}
	// A call they're ringing me with stops, quietly.
	if calls, err := s.Repo.RingingFrom(ctx, u.ID); err == nil {
		for _, c := range calls {
			if c.CalleeID == me {
				if done, err := s.Repo.TransitionCall(ctx, c.ID, []string{repo.CallRinging}, repo.CallMissed, s.Now()); err == nil {
					s.Hub.Publish(me, EventCallUpdate, s.view(ctx, done, me))
					s.Hub.Publish(u.ID, EventCallUpdate, s.view(ctx, done, u.ID))
				}
			}
		}
	}
	// They aren't told.
	s.changed(me)
	return nil
}

func (s *SocialService) Unblock(ctx context.Context, me, other string) error {
	u, err := s.findID(ctx, me, other)
	if err != nil {
		return err
	}
	ok, err := s.Repo.Unblock(ctx, me, u.ID)
	if err != nil {
		return err
	}
	if !ok {
		return apperr.ErrNotFound
	}
	s.changed(me)
	return nil
}

func privacyView(p *repo.Privacy) *Privacy {
	return &Privacy{Calls: p.Calls, DoNotDisturb: p.DoNotDisturb, FriendRequests: p.FriendRequests}
}

func (s *SocialService) Privacy(ctx context.Context, me string) (*Privacy, error) {
	p, err := s.Repo.Privacy(ctx, me)
	if err != nil {
		return nil, err
	}
	return privacyView(p), nil
}

func (s *SocialService) UpdatePrivacy(ctx context.Context, me string, patch PrivacyPatch) (*Privacy, error) {
	p, err := s.Repo.Privacy(ctx, me)
	if err != nil {
		return nil, err
	}
	if patch.Calls != nil {
		switch *patch.Calls {
		case repo.CallsNobody, repo.CallsFriends, repo.CallsEveryone:
			p.Calls = *patch.Calls
		default:
			return nil, apperr.InvalidField("calls", "must be nobody, friends or everyone")
		}
	}
	if patch.FriendRequests != nil {
		switch *patch.FriendRequests {
		case repo.RequestsNobody, repo.RequestsServers, repo.RequestsEveryone:
			p.FriendRequests = *patch.FriendRequests
		default:
			return nil, apperr.InvalidField("friend_requests", "must be nobody, servers or everyone")
		}
	}
	if patch.DoNotDisturb != nil {
		p.DoNotDisturb = *patch.DoNotDisturb
	}
	p.UserID = me
	p.UpdatedAt = s.Now()
	if err := s.Repo.SavePrivacy(ctx, p); err != nil {
		return nil, err
	}
	return privacyView(p), nil
}

func (s *SocialService) CanCall(ctx context.Context, callerID, calleeID string) (string, error) {
	if callerID == calleeID {
		return "", ErrSelf
	}
	rel, err := s.Repo.Relation(ctx, calleeID, callerID)
	if err != nil {
		return "", err
	}
	pv, err := s.Repo.Privacy(ctx, calleeID)
	if err != nil {
		return "", err
	}
	switch o, why := DecideCall(rel, pv); o {
	case Refused:
		return why, nil
	case Ring:
		return "ok", nil
	}
	return "unavailable", nil
}
