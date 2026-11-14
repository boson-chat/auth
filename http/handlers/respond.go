// Package handlers implements the REST/JSON API. Handlers only talk to
// services.
package handlers

import (
	"encoding/json"
	"errors"
	"mime"
	nethttp "net/http"
	"reflect"
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
	// Code repeats Error for clients that read the code from "code".
	Code string `json:"code"`
	// Field is the request field a 400 is about, when there is one.
	Field string `json:"field,omitempty"`
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
		writeJSON(w, e.Status, errorBody{Error: e.Code, Message: e.Message, Code: e.Code, Field: e.Field})
		return
	}
	logger.FromCtx(r.Context()).Error().Err(err).Str("path", r.URL.Path).Msg("internal error")
	writeJSON(w, nethttp.StatusInternalServerError, errorBody{Error: "internal_error", Message: "internal error", Code: "internal_error"})
}

var errUnsupportedMedia = apperr.New(nethttp.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")

// decode reads a JSON body. Requiring application/json also means a plain
// HTML form on another site can't submit to us (it can't set that type
// without a CORS preflight).
func decode(w nethttp.ResponseWriter, r *nethttp.Request, dst any) error {
	return decodeLimit(w, r, dst, maxBody)
}

// decodeLimit is decode with a body limit of limit bytes.
func decodeLimit(w nethttp.ResponseWriter, r *nethttp.Request, dst any, limit int64) error {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		return errUnsupportedMedia
	}
	r.Body = nethttp.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var mbe *nethttp.MaxBytesError
		if errors.As(err, &mbe) {
			return apperr.New(nethttp.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
		}
		var ute *json.UnmarshalTypeError
		if errors.As(err, &ute) && ute.Field != "" {
			return apperr.Invalid(ute.Field + " must be " + jsonTypeName(ute.Type.Kind()))
		}
		return apperr.Invalid("malformed JSON body")
	}
	return nil
}

// jsonTypeName names the JSON type a Go kind decodes from, for error messages.
func jsonTypeName(k reflect.Kind) string {
	switch k {
	case reflect.Bool:
		return "a boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "an integer"
	case reflect.Float32, reflect.Float64:
		return "a number"
	case reflect.String:
		return "a string"
	case reflect.Slice, reflect.Array:
		return "an array"
	default:
		return "an object"
	}
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
