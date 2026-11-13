// Package handlers implements the REST/JSON API. Handlers only talk to
// services.
package handlers

import (
	"encoding/json"
	"errors"
	"mime"
	nethttp "net/http"
	"time"

	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories/session"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/logger"
)

const maxBody = 64 << 10

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w nethttp.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// writeError renders apperr errors as-is and everything else as a generic 500.
func writeError(w nethttp.ResponseWriter, r *nethttp.Request, err error) {
	if e, ok := apperr.As(err); ok {
		writeJSON(w, e.Status, errorBody{Error: e.Code, Message: e.Message})
		return
	}
	logger.FromCtx(r.Context()).Error().Err(err).Str("path", r.URL.Path).Msg("internal error")
	writeJSON(w, nethttp.StatusInternalServerError, errorBody{Error: "internal_error", Message: "internal error"})
}

var errUnsupportedMedia = apperr.New(nethttp.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")

// decode reads a JSON body. Requiring application/json also means a plain
// HTML form on another site can't submit to us (it can't set that type
// without a CORS preflight).
func decode(w nethttp.ResponseWriter, r *nethttp.Request, dst any) error {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		return errUnsupportedMedia
	}
	r.Body = nethttp.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var mbe *nethttp.MaxBytesError
		if errors.As(err, &mbe) {
			return apperr.New(nethttp.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
		}
		return apperr.Invalid("malformed JSON body")
	}
	return nil
}

// decodeOptional is decode for endpoints whose body may be empty.
func decodeOptional(w nethttp.ResponseWriter, r *nethttp.Request, dst any) error {
	if r.ContentLength == 0 {
		return nil
	}
	return decode(w, r, dst)
}

type userJSON struct {
	ID            string     `json:"id"`
	Username      string     `json:"username"`
	Email         *string    `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	DisplayName   string     `json:"display_name"`
	Role          string     `json:"role"`
	CreatedAt     time.Time  `json:"created_at"`
	DisabledAt    *time.Time `json:"disabled_at,omitempty"`
}

func toUser(u *user.User) userJSON {
	return userJSON{
		ID: u.ID, Username: u.Username, Email: u.Email, EmailVerified: u.EmailVerified(),
		DisplayName: u.DisplayName, Role: u.Role, CreatedAt: u.CreatedAt, DisabledAt: u.DisabledAt,
	}
}

type sessionJSON struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id,omitempty"`
	AuthMethod string    `json:"auth_method"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Current    bool      `json:"current,omitempty"`
}

func toSession(s *session.Session, currentID string, withUser bool) sessionJSON {
	out := sessionJSON{
		ID: s.ID, AuthMethod: s.AuthMethod, IP: s.IP, UserAgent: s.UserAgent,
		CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt, Current: s.ID == currentID,
	}
	if withUser {
		out.UserID = s.UserID
	}
	return out
}
