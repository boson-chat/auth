package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/boson-chat/auth/config"
)

// filesQuota sets per-user upload limits on the files service
// (PUT /internal/quota/{user} on its internal listener). The files service
// only reads sub from access tokens, so this override is how federated
// users get their own quota.
type filesQuota struct {
	base, token string
	client      *http.Client
}

func newFilesQuota(c config.FilesInternalConfig, client *http.Client) *filesQuota {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &filesQuota{base: strings.TrimRight(strings.TrimSpace(c.URL), "/"), token: c.Token, client: client}
}

func (f *filesQuota) enabled() bool { return f.base != "" && f.token != "" }

// quotaKey identifies a pair of limits ("" = the files defaults).
func quotaKey(quota, maxFile int64) string {
	if quota <= 0 && maxFile <= 0 {
		return ""
	}
	return strconv.FormatInt(quota, 10) + "/" + strconv.FormatInt(maxFile, 10)
}

func nullable(n int64) any {
	if n <= 0 {
		return nil
	}
	return n
}

// apply sets the override, or removes it when both limits are defaults.
func (f *filesQuota) apply(ctx context.Context, userID string, quota, maxFile int64) error {
	u := f.base + "/internal/quota/" + url.PathEscape(userID)
	method, body := http.MethodDelete, io.Reader(nil)
	if quotaKey(quota, maxFile) != "" {
		b, _ := json.Marshal(map[string]any{"quota_bytes": nullable(quota), "max_file_bytes": nullable(maxFile)})
		method, body = http.MethodPut, bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-Internal-Token", f.token)
	req.Header.Set("X-Acting-User", "auth-federation")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 && !(method == http.MethodDelete && resp.StatusCode == http.StatusNotFound) {
		return fmt.Errorf("files %s %s: HTTP %d", method, u, resp.StatusCode)
	}
	return nil
}

// jsonList encodes a domain list for a settings patch.
func jsonList(l []string) (json.RawMessage, error) {
	if l == nil {
		l = []string{}
	}
	return json.Marshal(l)
}
