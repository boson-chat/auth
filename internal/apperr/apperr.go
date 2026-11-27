// Package apperr defines the client-facing errors services return. The HTTP
// layer renders them as {"error": code, "message": message} with Status.
// Any other error is an internal error and is never shown to clients.
package apperr

import (
	"errors"
	"net/http"
	"time"
)

type Error struct {
	Status  int
	Code    string
	Message string
	// Field names the request field Message is about (400s), if one.
	Field string
	// RetryAfter, when set, is sent as the Retry-After header (429s).
	RetryAfter time.Duration
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// New makes an Error.
func New(status int, code, msg string) *Error {
	return &Error{Status: status, Code: code, Message: msg}
}

// Invalid is a 400 for a bad field value.
func Invalid(msg string) *Error { return New(http.StatusBadRequest, "invalid_request", msg) }

// InvalidField is a 400 about one request field: the message starts with
// the field's name and the body carries it as "field".
func InvalidField(field, msg string) *Error {
	e := Invalid(field + " " + msg)
	e.Field = field
	return e
}

// WithRetryAfter returns a copy of e with RetryAfter d.
func (e *Error) WithRetryAfter(d time.Duration) *Error {
	c := *e
	c.RetryAfter = d
	return &c
}

// WithMessage returns a copy of e with another message.
func (e *Error) WithMessage(msg string) *Error {
	c := *e
	c.Message = msg
	return &c
}

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
	ErrNoEmail            = New(http.StatusBadRequest, "no_email", "this account has no email address")
	ErrAlreadyVerified    = New(http.StatusConflict, "already_verified", "the email address is already verified")
	// ErrEmailNotConfigured: no mail server is configured (SMTP_HOST is
	// empty), so nothing can be emailed.
	ErrEmailNotConfigured = New(http.StatusConflict, "email_not_configured",
		"this network has no mail server configured, so it can't send email")
	// ErrUserDisabled is the admin-facing conflict for acting on a disabled account.
	ErrUserDisabled = New(http.StatusConflict, "account_disabled", "this account is disabled")
)
