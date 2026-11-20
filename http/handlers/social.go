package handlers

import (
	"context"
	nethttp "net/http"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/services/social"
	"github.com/boson-chat/auth/internal/textutil"
)

// Friends, blocks, privacy settings, private calls and the event feed
// (docs/friends-calls.md).

func (h *Handlers) registerSocial(mux *nethttp.ServeMux) {
	if h.Social == nil {
		return
	}
	mux.HandleFunc("GET /v1/friends", h.authed(h.friends))
	mux.HandleFunc("POST /v1/friends/requests", h.authed(h.social(h.requestFriend)))
	mux.HandleFunc("POST /v1/friends/requests/{id}/accept", h.authed(h.social(h.acceptFriend)))
	mux.HandleFunc("DELETE /v1/friends/requests/{id}", h.authed(h.social(h.deleteFriendRequest)))
	mux.HandleFunc("PATCH /v1/friends/{id}", h.authed(h.social(h.patchFriend)))
	mux.HandleFunc("DELETE /v1/friends/{id}", h.authed(h.social(h.removeFriend)))
	mux.HandleFunc("POST /v1/blocks", h.authed(h.social(h.block)))
	mux.HandleFunc("DELETE /v1/blocks/{id}", h.authed(h.social(h.unblock)))
	mux.HandleFunc("GET /v1/users/{username}/relation", h.authed(h.relation))
	mux.HandleFunc("GET /v1/me/privacy", h.authed(h.privacy))
	mux.HandleFunc("PATCH /v1/me/privacy", h.authed(h.updatePrivacy))

	mux.HandleFunc("POST /v1/calls", h.authed(h.social(h.startCall)))
	mux.HandleFunc("POST /v1/calls/{id}/accept", h.authed(h.acceptCall))
	mux.HandleFunc("POST /v1/calls/{id}/decline", h.authed(h.declineCall))
	mux.HandleFunc("POST /v1/calls/{id}/cancel", h.authed(h.cancelCall))
	mux.HandleFunc("POST /v1/calls/{id}/end", h.authed(h.endCall))
	mux.HandleFunc("POST /v1/calls/{id}/token", h.authed(h.callToken))
	mux.HandleFunc("GET /v1/calls/missed", h.authed(h.missedCalls))
	mux.HandleFunc("POST /v1/calls/missed/seen", h.authed(h.missedSeen))

	mux.HandleFunc("GET /v1/events", h.authed(h.events))
}

// social rate-limits the actions that reach other people (requests, calls,
// blocks): per account.
func (h *Handlers) social(next nethttp.HandlerFunc) nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if !h.Limits.allow(w, r, BucketSocial, principalFrom(r).UserID) {
			return
		}
		next(w, r)
	}
}

func pathID(r *nethttp.Request) string {
	id := r.PathValue("id")
	if !textutil.Storable(id) || len(id) > 64 {
		return ""
	}
	return id
}

func (h *Handlers) friends(w nethttp.ResponseWriter, r *nethttp.Request) {
	out, err := h.Social.Friends(r.Context(), principalFrom(r).UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, out)
}

// target is a body naming someone: {username} or {user_id}.
type target struct {
	Username string `json:"username"`
	UserID   string `json:"user_id"`
}

func (t target) name() string {
	if t.UserID != "" {
		return t.UserID
	}
	return t.Username
}

func (h *Handlers) requestFriend(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req target
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	p := principalFrom(r)
	out, err := h.Social.RequestFriend(r.Context(), p.User, req.name())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, out)
}

func (h *Handlers) noContent(w nethttp.ResponseWriter, r *nethttp.Request, err error) {
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(nethttp.StatusNoContent)
}

func (h *Handlers) acceptFriend(w nethttp.ResponseWriter, r *nethttp.Request) {
	h.noContent(w, r, h.Social.AcceptRequest(r.Context(), principalFrom(r).UserID, pathID(r)))
}

func (h *Handlers) deleteFriendRequest(w nethttp.ResponseWriter, r *nethttp.Request) {
	h.noContent(w, r, h.Social.DeleteRequest(r.Context(), principalFrom(r).UserID, pathID(r)))
}

func (h *Handlers) removeFriend(w nethttp.ResponseWriter, r *nethttp.Request) {
	h.noContent(w, r, h.Social.RemoveFriend(r.Context(), principalFrom(r).UserID, pathID(r)))
}

func (h *Handlers) patchFriend(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req struct {
		CanCallAnytime *bool `json:"can_call_anytime"`
	}
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if req.CanCallAnytime == nil {
		writeError(w, r, apperr.InvalidField("can_call_anytime", "is required"))
		return
	}
	h.noContent(w, r, h.Social.SetAnytime(r.Context(), principalFrom(r).UserID, pathID(r), *req.CanCallAnytime))
}

func (h *Handlers) block(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req target
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	h.noContent(w, r, h.Social.Block(r.Context(), principalFrom(r).UserID, req.name()))
}

func (h *Handlers) unblock(w nethttp.ResponseWriter, r *nethttp.Request) {
	h.noContent(w, r, h.Social.Unblock(r.Context(), principalFrom(r).UserID, pathID(r)))
}

func (h *Handlers) relation(w nethttp.ResponseWriter, r *nethttp.Request) {
	name := r.PathValue("username")
	if nick.Validate(name) != nil {
		writeError(w, r, social.ErrUserNotFound)
		return
	}
	out, err := h.Social.Relation(r.Context(), principalFrom(r).UserID, name)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, out)
}

func (h *Handlers) privacy(w nethttp.ResponseWriter, r *nethttp.Request) {
	out, err := h.Social.Privacy(r.Context(), principalFrom(r).UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, out)
}

func (h *Handlers) updatePrivacy(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req social.PrivacyPatch
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	out, err := h.Social.UpdatePrivacy(r.Context(), principalFrom(r).UserID, req)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, out)
}

func (h *Handlers) startCall(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req struct {
		target
		Video bool `json:"video"`
	}
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	call, err := h.Social.StartCall(r.Context(), principalFrom(r), req.name(), req.Video)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusCreated, map[string]any{"call": call})
}

func (h *Handlers) acceptCall(w nethttp.ResponseWriter, r *nethttp.Request) {
	call, voice, err := h.Social.AcceptCall(r.Context(), principalFrom(r), pathID(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"call": call, "voice": voice})
}

func (h *Handlers) callAction(fn func(ctx context.Context, me, id string) (*social.CallView, error)) nethttp.HandlerFunc {
	return func(w nethttp.ResponseWriter, r *nethttp.Request) {
		call, err := fn(r.Context(), principalFrom(r).UserID, pathID(r))
		if err != nil {
			writeError(w, r, err)
			return
		}
		writeJSON(w, nethttp.StatusOK, map[string]any{"call": call})
	}
}

func (h *Handlers) declineCall(w nethttp.ResponseWriter, r *nethttp.Request) {
	h.callAction(h.Social.DeclineCall)(w, r)
}

func (h *Handlers) cancelCall(w nethttp.ResponseWriter, r *nethttp.Request) {
	h.callAction(h.Social.CancelCall)(w, r)
}

func (h *Handlers) endCall(w nethttp.ResponseWriter, r *nethttp.Request) {
	h.callAction(h.Social.EndCall)(w, r)
}

func (h *Handlers) callToken(w nethttp.ResponseWriter, r *nethttp.Request) {
	voice, err := h.Social.CallToken(r.Context(), principalFrom(r), pathID(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"voice": voice})
}

func (h *Handlers) missedCalls(w nethttp.ResponseWriter, r *nethttp.Request) {
	out, err := h.Social.Missed(r.Context(), principalFrom(r).UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, out)
}

func (h *Handlers) missedSeen(w nethttp.ResponseWriter, r *nethttp.Request) {
	h.noContent(w, r, h.Social.MarkMissedSeen(r.Context(), principalFrom(r).UserID))
}

// events: GET /v1/events?cursor= is the long poll (held up to 25 s).
func (h *Handlers) events(w nethttp.ResponseWriter, r *nethttp.Request) {
	cursor := r.URL.Query().Get("cursor")
	if len(cursor) > 64 {
		cursor = ""
	}
	// Past the listener's write timeout if one is ever set below the wait.
	_ = nethttp.NewResponseController(w).SetWriteDeadline(time.Now().Add(social.PollWait + 15*time.Second))
	out, err := h.Social.Poll(r.Context(), principalFrom(r).UserID, cursor)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, nethttp.StatusOK, out)
}

// internalCanCall: GET /internal/v1/calls/check?from=<user id>&to=<user id>
// → {result: ok | friends_only | calls_off | you_blocked | unavailable}.
// The "may A ring B?" check for other services.
func (h *Handlers) internalCanCall(w nethttp.ResponseWriter, r *nethttp.Request) {
	q := r.URL.Query()
	res, err := h.Social.CanCall(r.Context(), q.Get("from"), q.Get("to"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]string{"result": res})
}
