// Package apperr defines the client-facing errors services return. The HTTP
// layer renders them as {"error": code, "message": message} with Status.
// Any other error is an internal error and is never shown to clients.
package apperr

import (
	"errors"
	"net/http"
)

type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// New makes an Error.
func New(status int, code, msg string) *Error {
	return &Error{Status: status, Code: code, Message: msg}
}

// Invalid is a 400 for a bad field value.
func Invalid(msg string) *Error { return New(http.StatusBadRequest, "invalid_request", msg) }

// As extracts an *Error.
func As(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

var (
	ErrInvalidCredentials = New(http.StatusUnauthorized, "invalid_credentials", "invalid login or password")
	ErrAccountDisabled    = New(http.StatusForbidden, "account_disabled", "this account is disabled")
	ErrEmailNotVerified   = New(http.StatusForbidden, "email_not_verified", "verify your email address before signing in")
	ErrUnauthenticated    = New(http.StatusUnauthorized, "unauthenticated", "missing or invalid access token")
	ErrForbidden          = New(http.StatusForbidden, "forbidden", "not allowed")
	ErrInvalidRefresh     = New(http.StatusUnauthorized, "invalid_refresh_token", "refresh token is invalid or expired")
	ErrInvalidToken       = New(http.StatusBadRequest, "invalid_token", "token is invalid, expired or already used")
	ErrRegistrationClosed = New(http.StatusForbidden, "registration_closed", "registration is closed")
	ErrInviteRequired     = New(http.StatusForbidden, "invite_required", "a valid invite code is required")
	ErrUsernameTaken      = New(http.StatusConflict, "username_taken", "that username is taken")
	ErrEmailTaken         = New(http.StatusConflict, "email_taken", "that email address is already registered")
	ErrNotFound           = New(http.StatusNotFound, "not_found", "not found")
	ErrNoPassword         = New(http.StatusBadRequest, "no_password", "this account has no password")
)
