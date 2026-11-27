package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Account is a bridge account as the managed API returns it.
type Account struct {
	Username string   `json:"username"`
	Subject  string   `json:"subject"`
	Email    string   `json:"email"`
	Nick     string   `json:"nick"`
	AltNick  string   `json:"altNick"`
	Ident    string   `json:"ident"`
	Realname string   `json:"realname"`
	Disabled bool     `json:"disabled"`
	Auth     AuthView `json:"auth"`
}

// AuthView is an account's services login (never the password).
type AuthView struct {
	Method      string `json:"method"`
	Account     string `json:"account"`
	HasPassword bool   `json:"hasPassword"`
}

// Put is the body of PUT /api/managed/users/{username}. Auth nil leaves
// the account's services login as it is.
type Put struct {
	Subject  string `json:"subject"`
	Email    string `json:"email"`
	Nick     string `json:"nick"`
	AltNick  string `json:"altNick"`
	Ident    string `json:"ident"`
	Realname string `json:"realname"`
	Disabled bool   `json:"disabled"`
	Auth     *Auth  `json:"auth,omitempty"`
}

// Auth is the services login sent to the bridge.
type Auth struct {
	Method   string `json:"method"`
	Account  string `json:"account,omitempty"`
	Password string `json:"password,omitempty"`
}

// String never shows the password (a Put or Auth printed by mistake).
func (a Auth) String() string {
	return fmt.Sprintf("{%s %s password:%t}", a.Method, a.Account, a.Password != "")
}

// GoString hides the password from %#v too.
func (a Auth) GoString() string { return a.String() }

// Client is evrd's managed API.
type Client interface {
	List(ctx context.Context) ([]Account, error)
	// Get returns nil, nil when there's no such account.
	Get(ctx context.Context, username string) (*Account, error)
	Put(ctx context.Context, username string, p Put) error
	// Delete succeeds when the account is already gone.
	Delete(ctx context.Context, username string) error
	// PutSettings changes the bridge's runtime settings (the fields set)
	// and returns those in effect; a 404 StatusError on an evrd before 0.61.
	PutSettings(ctx context.Context, p Settings) (*Settings, error)
}

// StatusError is a managed API answer other than 2xx.
type StatusError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d %s", e.Method, e.Path, e.Status, e.Body)
}

// IsStatus reports whether err is a managed API answer with that status.
func IsStatus(err error, status int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == status
}

// HTTPClient talks to the managed API.
type HTTPClient struct {
	base, token string
	c           *http.Client
}

// NewHTTPClient is the managed API at base (http://evrd-links:8098).
// c nil: a client with timeout.
func NewHTTPClient(base, token string, timeout time.Duration, c *http.Client) *HTTPClient {
	if c == nil {
		c = &http.Client{Timeout: timeout}
	}
	return &HTTPClient{base: strings.TrimRight(strings.TrimSpace(base), "/"), token: strings.TrimSpace(token), c: c}
}

func userPath(username string) string { return "/api/managed/users/" + url.PathEscape(username) }

func (h *HTTPClient) do(ctx context.Context, method, path string, body, out any, secret string) error {
	var r io.Reader
	if body != nil {
		j, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(j)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.base+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.c.Do(req)
	if err != nil {
		// url.Error names the URL, never the body.
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return &StatusError{Method: method, Path: path, Status: resp.StatusCode, Body: errorText(data, secret)}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// errorText is an error answer fit for logs: short, one line, and never
// the password, should the bridge echo it.
func errorText(data []byte, secret string) string {
	s := string(data)
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &e) == nil && e.Error != "" {
		s = e.Error
	}
	if secret != "" {
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func (h *HTTPClient) List(ctx context.Context) ([]Account, error) {
	var r struct {
		Users []Account `json:"users"`
	}
	err := h.do(ctx, http.MethodGet, "/api/managed/users", nil, &r, "")
	return r.Users, err
}

func (h *HTTPClient) Get(ctx context.Context, username string) (*Account, error) {
	var a Account
	err := h.do(ctx, http.MethodGet, userPath(username), nil, &a, "")
	if IsStatus(err, http.StatusNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (h *HTTPClient) Put(ctx context.Context, username string, p Put) error {
	secret := ""
	if p.Auth != nil {
		secret = p.Auth.Password
	}
	return h.do(ctx, http.MethodPut, userPath(username), p, nil, secret)
}

func (h *HTTPClient) Delete(ctx context.Context, username string) error {
	err := h.do(ctx, http.MethodDelete, userPath(username), nil, nil, "")
	if IsStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}
