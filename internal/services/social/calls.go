package social

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/boson-chat/auth/internal/db/repositories"
	repo "github.com/boson-chat/auth/internal/db/repositories/social"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/internal/services/authn"
)

// CallIDPrefix: call ids are cal_<ULID>.
const CallIDPrefix = "cal"

// MissedEvent is the missed event's data.
type MissedEvent struct {
	Count int64 `json:"count"`
}

// RoomFor is a call's voice room.
func RoomFor(callID string) string { return CallRoomPrefix + callID }

// view is c as userID (one of its two people) sees it.
func (s *SocialService) view(ctx context.Context, c *repo.Call, userID string) CallView {
	v := CallView{ID: c.ID, Room: RoomFor(c.ID), Video: c.Video, State: c.State, Direction: "incoming",
		CreatedAt: c.CreatedAt, ExpiresAt: c.CreatedAt.Add(RingTimeout)}
	peer := c.CallerID
	if userID == c.CallerID {
		v.Direction, peer = "outgoing", c.CalleeID
	}
	v.Peer = Person{UserID: peer}
	if u, err := s.Users.FindByID(ctx, peer); err == nil {
		v.Peer = person(u)
	}
	return v
}

func (s *SocialService) findCall(ctx context.Context, me, id string) (*repo.Call, error) {
	if !ids.HasPrefix(id, CallIDPrefix) {
		return nil, ErrCallNotFound
	}
	c, err := s.Repo.FindCall(ctx, id)
	if errors.Is(err, repositories.ErrNotFound) {
		return nil, ErrCallNotFound
	}
	if err != nil {
		return nil, err
	}
	if c.CallerID != me && c.CalleeID != me {
		return nil, ErrCallNotFound
	}
	return c, nil
}

// publishCall tells both people (all their apps) about c's new state, and
// the callee their missed count when it was missed.
func (s *SocialService) publishCall(ctx context.Context, c *repo.Call) {
	s.Hub.Publish(c.CallerID, EventCallUpdate, s.view(ctx, c, c.CallerID))
	if c.State == repo.CallUnavailable {
		return // never reached the callee
	}
	s.Hub.Publish(c.CalleeID, EventCallUpdate, s.view(ctx, c, c.CalleeID))
	if c.State == repo.CallMissed {
		s.publishMissed(ctx, c.CalleeID)
	}
}

func (s *SocialService) publishMissed(ctx context.Context, userID string) {
	_, n, err := s.Repo.Missed(ctx, userID, 0)
	if err != nil {
		logger.FromCtx(ctx).Warn().Err(err).Msg("missed call count")
		return
	}
	s.Hub.Publish(userID, EventMissed, MissedEvent{Count: n})
}

func (s *SocialService) transition(ctx context.Context, c *repo.Call, from []string, to string) (*repo.Call, error) {
	done, err := s.Repo.TransitionCall(ctx, c.ID, from, to, s.Now())
	if errors.Is(err, repo.ErrStateChanged) {
		return nil, ErrCallOver
	}
	if err != nil {
		return nil, err
	}
	s.publishCall(ctx, done)
	return done, nil
}

func (s *SocialService) StartCall(ctx context.Context, p *authn.Principal, target string, video bool) (*CallView, error) {
	to, err := s.find(ctx, p.UserID, target)
	if err != nil {
		return nil, err
	}
	// The callee's side decides: their settings, their view of the caller.
	rel, err := s.Repo.Relation(ctx, to.ID, p.UserID)
	if err != nil {
		return nil, err
	}
	pv, err := s.Repo.Privacy(ctx, to.ID)
	if err != nil {
		return nil, err
	}
	outcome, why := DecideCall(rel, pv)
	if outcome == Refused {
		return nil, refusal(why, to.Username)
	}
	// One outgoing call at a time: an earlier one still ringing stops.
	if prev, err := s.Repo.RingingFrom(ctx, p.UserID); err == nil {
		for _, c := range prev {
			_, _ = s.transition(ctx, c, []string{repo.CallRinging}, repo.CallMissed)
		}
	}
	now := s.Now()
	c := &repo.Call{ID: ids.New(CallIDPrefix), CallerID: p.UserID, CalleeID: to.ID, Video: video, CreatedAt: now}
	switch {
	case outcome == Silent:
		c.State, c.EndedAt = repo.CallUnavailable, &now
	case outcome == Missed || !s.Hub.Online(to.ID):
		// Do not disturb, or no app open: a missed call, nothing rings.
		c.State, c.EndedAt = repo.CallMissed, &now
	default:
		c.State = repo.CallRinging
	}
	if err := s.Repo.CreateCall(ctx, c); err != nil {
		return nil, err
	}
	v := s.view(ctx, c, p.UserID)
	switch c.State {
	case repo.CallRinging:
		s.Hub.Publish(to.ID, EventCallRing, s.view(ctx, c, to.ID))
	case repo.CallMissed:
		s.publishMissed(ctx, to.ID)
	}
	if c.State != repo.CallRinging {
		// Blocked, Do not disturb and offline all look the same to the caller.
		v.State = repo.CallUnavailable
	}
	return &v, nil
}

func (s *SocialService) grant(ctx context.Context, p *authn.Principal, c *repo.Call) (*VoiceGrant, error) {
	room := RoomFor(c.ID)
	tok, exp, err := s.MintToken(ctx, p, room)
	if err != nil {
		return nil, err
	}
	return &VoiceGrant{Token: tok, ExpiresIn: int64(time.Until(exp).Seconds()), Room: room}, nil
}

func (s *SocialService) AcceptCall(ctx context.Context, p *authn.Principal, id string) (*CallView, *VoiceGrant, error) {
	c, err := s.findCall(ctx, p.UserID, id)
	if err != nil {
		return nil, nil, err
	}
	if c.CalleeID != p.UserID {
		return nil, nil, ErrCallNotFound
	}
	done, err := s.transition(ctx, c, []string{repo.CallRinging}, repo.CallAnswered)
	if err != nil {
		return nil, nil, err
	}
	g, err := s.grant(ctx, p, done)
	if err != nil {
		return nil, nil, err
	}
	v := s.view(ctx, done, p.UserID)
	return &v, g, nil
}

func (s *SocialService) DeclineCall(ctx context.Context, me, id string) (*CallView, error) {
	c, err := s.findCall(ctx, me, id)
	if err != nil {
		return nil, err
	}
	if c.CalleeID != me {
		return nil, ErrCallNotFound
	}
	done, err := s.transition(ctx, c, []string{repo.CallRinging}, repo.CallDeclined)
	if err != nil {
		return nil, err
	}
	v := s.view(ctx, done, me)
	return &v, nil
}

func (s *SocialService) CancelCall(ctx context.Context, me, id string) (*CallView, error) {
	c, err := s.findCall(ctx, me, id)
	if err != nil {
		return nil, err
	}
	if c.CallerID != me {
		return nil, ErrCallNotFound
	}
	// The callee sees it as a missed call.
	done, err := s.transition(ctx, c, []string{repo.CallRinging}, repo.CallMissed)
	if err != nil {
		return nil, err
	}
	v := s.view(ctx, done, me)
	return &v, nil
}

func (s *SocialService) EndCall(ctx context.Context, me, id string) (*CallView, error) {
	c, err := s.findCall(ctx, me, id)
	if err != nil {
		return nil, err
	}
	switch {
	case c.State == repo.CallRinging && c.CallerID == me:
		return s.CancelCall(ctx, me, id)
	case c.State == repo.CallRinging:
		return s.DeclineCall(ctx, me, id)
	}
	done, err := s.transition(ctx, c, []string{repo.CallAnswered}, repo.CallEnded)
	if err != nil {
		return nil, err
	}
	v := s.view(ctx, done, me)
	return &v, nil
}

func (s *SocialService) CallToken(ctx context.Context, p *authn.Principal, id string) (*VoiceGrant, error) {
	c, err := s.findCall(ctx, p.UserID, id)
	if err != nil {
		return nil, err
	}
	if c.State != repo.CallAnswered {
		return nil, ErrCallOver
	}
	return s.grant(ctx, p, c)
}

func (s *SocialService) Missed(ctx context.Context, me string) (*MissedList, error) {
	calls, n, err := s.Repo.Missed(ctx, me, missedListLimit)
	if err != nil {
		return nil, err
	}
	out := &MissedList{Count: n, Calls: make([]CallView, 0, len(calls))}
	for _, c := range calls {
		out.Calls = append(out.Calls, s.view(ctx, c, me))
	}
	return out, nil
}

func (s *SocialService) MarkMissedSeen(ctx context.Context, me string) error {
	if err := s.Repo.MarkMissedSeen(ctx, me); err != nil {
		return err
	}
	s.Hub.Publish(me, EventMissed, MissedEvent{Count: 0})
	return nil
}

func (s *SocialService) snapshot(ctx context.Context, me string) (*Snapshot, error) {
	ringing, err := s.Repo.RingingFor(ctx, me, s.Now().Add(-RingTimeout))
	if err != nil {
		return nil, err
	}
	_, missed, err := s.Repo.Missed(ctx, me, 0)
	if err != nil {
		return nil, err
	}
	in, err := s.Repo.IncomingRequests(ctx, me)
	if err != nil {
		return nil, err
	}
	snap := &Snapshot{Ringing: make([]CallView, 0, len(ringing)), Missed: missed, PendingRequests: len(in)}
	for _, c := range ringing {
		snap.Ringing = append(snap.Ringing, s.view(ctx, c, me))
	}
	return snap, nil
}

func (s *SocialService) Poll(ctx context.Context, me, cursor string) (*PollResult, error) {
	events, next, reset := s.Hub.Poll(ctx, me, cursor, s.PollWait)
	res := &PollResult{Cursor: next, Events: events, Reset: reset}
	if res.Events == nil {
		res.Events = []Event{}
	}
	if reset {
		snap, err := s.snapshot(ctx, me)
		if err != nil {
			return nil, err
		}
		res.Snapshot = snap
	}
	return res, nil
}

// Sweep expires unanswered calls once (Run calls it every second).
func (s *SocialService) Sweep(ctx context.Context) {
	now := s.Now()
	expired, err := s.Repo.ExpireRinging(ctx, now.Add(-RingTimeout), now)
	if err != nil {
		if ctx.Err() == nil {
			logger.FromCtx(ctx).Warn().Err(err).Msg("expiring calls")
		}
		return
	}
	slices.SortFunc(expired, func(a, b *repo.Call) int { return a.CreatedAt.Compare(b.CreatedAt) })
	for _, c := range expired {
		s.publishCall(ctx, c)
	}
}

func (s *SocialService) Run(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	clean := time.NewTicker(10 * time.Minute)
	defer clean.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.Sweep(ctx)
		case <-clean.C:
			now := s.Now()
			if _, err := s.Repo.EndStale(ctx, now.Add(-staleCall), now); err != nil && ctx.Err() == nil {
				logger.FromCtx(ctx).Warn().Err(err).Msg("ending stale calls")
			}
			if err := s.Repo.DeleteOldCalls(ctx, now.Add(-keepCalls)); err != nil && ctx.Err() == nil {
				logger.FromCtx(ctx).Warn().Err(err).Msg("deleting old calls")
			}
			s.Hub.Prune()
		}
	}
}
