package social

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErgoChannels says which IRC channels an account's client is in right now,
// from Ergo's HTTP API (POST /v1/whois, bearer ERGO_API_TOKEN). It backs the
// "People in my servers" friend request setting: someone may send you a
// request when you share a channel. nil (no ERGO_API_URL): nobody counts as
// sharing one, so that setting lets no one through.
type ErgoChannels interface {
	Channels(ctx context.Context, account string) (map[string]bool, error)
}

var errErgo = errors.New("ergo: lookup failed")

type ergoClient struct {
	url, token string
	http       *http.Client
}

// NewErgoChannels returns nil when url or token is empty.
func NewErgoChannels(url, token string) ErgoChannels {
	if url == "" || token == "" {
		return nil
	}
	return &ergoClient{url: strings.TrimRight(url, "/"), token: token, http: &http.Client{Timeout: 3 * time.Second}}
}

func (c *ergoClient) Channels(ctx context.Context, account string) (map[string]bool, error) {
	body, _ := json.Marshal(map[string]string{"nickname": account})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/v1/whois", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errErgo, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", errErgo, res.StatusCode)
	}
	var who struct {
		Success  bool   `json:"success"`
		Present  bool   `json:"present"`
		Account  string `json:"account"`
		Channels []struct {
			Name string `json:"name"`
		} `json:"channels"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&who); err != nil {
		return nil, fmt.Errorf("%w: %v", errErgo, err)
	}
	out := map[string]bool{}
	// The stack's Ergo forces nick = account; a different account on that
	// nick isn't them.
	if who.Success && who.Present && strings.EqualFold(who.Account, account) {
		for _, ch := range who.Channels {
			out[strings.ToLower(ch.Name)] = true
		}
	}
	return out, nil
}

// shareChannel reports whether a and b are in a common channel.
func shareChannel(ctx context.Context, e ErgoChannels, a, b string) (bool, error) {
	if e == nil {
		return false, nil
	}
	ca, err := e.Channels(ctx, a)
	if err != nil {
		return false, err
	}
	if len(ca) == 0 {
		return false, nil
	}
	cb, err := e.Channels(ctx, b)
	if err != nil {
		return false, err
	}
	for ch := range cb {
		if ca[ch] {
			return true, nil
		}
	}
	return false, nil
}
