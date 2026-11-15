package handlers

import (
	"bytes"
	"encoding/json"
	nethttp "net/http"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/perm"
	"github.com/boson-chat/auth/internal/services/rolechannels"
)

func (h *Handlers) registerRoleChannels(mux *nethttp.ServeMux) {
	view, manage := h.allow(perm.AdminPanel, perm.RolesManage), h.allow(perm.RolesManage)
	mux.HandleFunc("GET /v1/admin/roles/{id}/channels", view(h.adminRoleChannels))
	mux.HandleFunc("PUT /v1/admin/roles/{id}/channels", manage(h.adminSetRoleChannels))
	mux.HandleFunc("GET /v1/admin/channel-access", view(h.adminChannelAccess))
	mux.HandleFunc("PUT /v1/admin/channel-access", manage(h.adminSetChannelAccess))
	mux.HandleFunc("GET /v1/me/channels", h.authed(h.myChannels))
}

func (h *Handlers) registerInternalRoleChannels(mux *nethttp.ServeMux) {
	mux.HandleFunc("GET /internal/v1/irc/channel-access", h.internalOnly(h.internalChannelAccess))
	mux.HandleFunc("GET /internal/v1/irc/autojoin", h.internalOnly(h.internalAutojoin))
	mux.HandleFunc("POST /internal/v1/irc/autojoin", h.internalOnly(h.internalRecordAutojoin))
}

// roleChannelsBody is the body of PUT /v1/admin/roles/{id}/channels: a bare
// list, or {"channels": [...]}.
type roleChannelsBody struct {
	Channels []rolechannels.ChannelInput
}

func (b *roleChannelsBody) UnmarshalJSON(data []byte) error {
	return unmarshalListOrObject(data, "channels", &b.Channels)
}

type channelAccessBody struct {
	Channels []rolechannels.AccessInput
}

func (b *channelAccessBody) UnmarshalJSON(data []byte) error {
	return unmarshalListOrObject(data, "channels", &b.Channels)
}

func (h *Handlers) writeRoleChannels(w nethttp.ResponseWriter, roleID string, list []rolechannels.RoleChannel) {
	writeJSON(w, nethttp.StatusOK, map[string]any{"role_id": roleID, "channels": list})
}

// adminRoleChannels: GET /v1/admin/roles/{id}/channels ({id} may be "everyone").
func (h *Handlers) adminRoleChannels(w nethttp.ResponseWriter, r *nethttp.Request) {
	id, list, err := h.RoleChannels.ForRole(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	h.writeRoleChannels(w, id, list)
}

// adminSetRoleChannels: PUT /v1/admin/roles/{id}/channels with
// [{channel, autojoin}] (replaces the role's list).
func (h *Handlers) adminSetRoleChannels(w nethttp.ResponseWriter, r *nethttp.Request) {
	var body roleChannelsBody
	if err := decode(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	id, list, err := h.RoleChannels.SetForRole(r.Context(), principalFrom(r).UserID, r.PathValue("id"), body.Channels)
	if err != nil {
		writeError(w, r, err)
		return
	}
	h.writeRoleChannels(w, id, list)
}

// adminChannelAccess: GET /v1/admin/channel-access, every channel listed on
// a role or marked private.
func (h *Handlers) adminChannelAccess(w nethttp.ResponseWriter, r *nethttp.Request) {
	list, err := h.RoleChannels.Access(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"channels": list})
}

// adminSetChannelAccess: PUT /v1/admin/channel-access with
// [{channel, private}]: the private: true entries become the private
// channels (every other channel is public).
func (h *Handlers) adminSetChannelAccess(w nethttp.ResponseWriter, r *nethttp.Request) {
	var body channelAccessBody
	if err := decode(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	list, err := h.RoleChannels.SetAccess(r.Context(), principalFrom(r).UserID, body.Channels)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"channels": list})
}

// myChannels: GET /v1/me/channels, the channels the caller's roles give.
func (h *Handlers) myChannels(w nethttp.ResponseWriter, r *nethttp.Request) {
	list, err := h.RoleChannels.ForUser(r.Context(), principalFrom(r).UserID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, map[string]any{"channels": list})
}

// internalChannelAccess: GET /internal/v1/irc/channel-access, for RoleServ.
// ETag / If-None-Match with the feed version.
func (h *Handlers) internalChannelAccess(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Header.Get("If-None-Match") != "" {
		version, err := h.RoleChannels.FeedVersion(r.Context())
		if err != nil {
			writeError(w, r, err)
			return
		}
		if notModified(w, r, version) {
			return
		}
	}
	feed, err := h.RoleChannels.Feed(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+feed.Version+`"`)
	writeJSON(w, nethttp.StatusOK, feed)
}

// internalAutojoin: GET /internal/v1/irc/autojoin?account=
func (h *Handlers) internalAutojoin(w nethttp.ResponseWriter, r *nethttp.Request) {
	account := r.URL.Query().Get("account")
	if account == "" {
		writeError(w, r, apperr.Invalid("account is required"))
		return
	}
	aj, err := h.RoleChannels.Autojoin(r.Context(), account)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, aj)
}

type recordAutojoinReq struct {
	Account  string   `json:"account"`
	Channels []string `json:"channels"`
}

// internalRecordAutojoin: POST /internal/v1/irc/autojoin {account, channels}:
// RoleServ joined account to channels (for rejoin: once).
func (h *Handlers) internalRecordAutojoin(w nethttp.ResponseWriter, r *nethttp.Request) {
	var req recordAutojoinReq
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if req.Account == "" {
		writeError(w, r, apperr.Invalid("account is required"))
		return
	}
	aj, err := h.RoleChannels.RecordAutojoined(r.Context(), req.Account, req.Channels)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, nethttp.StatusOK, aj)
}

// unmarshalListOrObject decodes either a bare JSON list or an object with
// the list under key (null / missing = empty list).
func unmarshalListOrObject[T any](data []byte, key string, dst *[]T) error {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '{' {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		data = obj[key]
	}
	*dst = []T{}
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	return json.Unmarshal(data, dst)
}
