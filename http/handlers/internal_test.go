package handlers

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/reqmeta"
	"github.com/boson-chat/auth/metrics"
)

func TestForwardedClientIP(t *testing.T) {
	cases := map[string]struct {
		header string
		want   string
		ok     bool
	}{
		"none":        {"", "", false},
		"ipv4":        {"203.0.113.7", "203.0.113.7", true},
		"chain":       {"203.0.113.7, 10.0.0.2", "203.0.113.7", true},
		"ipv6":        {"2001:db8::1", "2001:db8::1", true},
		"mapped ipv4": {"::ffff:198.51.100.4", "198.51.100.4", true},
		"garbage":     {"not-an-ip", "", false},
		"spaces":      {"  192.0.2.9 ", "192.0.2.9", true},
	}
	for name, c := range cases {
		r := httptest.NewRequest("POST", "/internal/v1/verify-password", nil)
		if c.header != "" {
			r.Header.Set("X-Forwarded-For", c.header)
		}
		got, ok := ForwardedClientIP(r)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", name, got, ok, c.want, c.ok)
		}
	}
}

// One IRC client trying many accounts is stopped by the per-forwarded-IP
// bucket; another client behind the same IRC server is unaffected.
func TestInternalIPBucketLimitsPerForwardedIP(t *testing.T) {
	cfg := config.RateLimitConfig{Enabled: true, IPBurst: 2, IPPerMinute: 1, AccountBurst: 5, AccountPerMinute: 2}
	l := NewLimits(cfg, metrics.Noop())
	req := func(ip string) *nethttp.Request {
		r := httptest.NewRequest("POST", "/internal/v1/verify-password", nil)
		return r.WithContext(reqmeta.With(context.Background(), reqmeta.Meta{IP: ip}))
	}
	allowed := 0
	for range 10 {
		if l.allow(httptest.NewRecorder(), req("203.0.113.7"), BucketInternalIP, "") {
			allowed++
		}
	}
	if allowed != cfg.IPBurst*2 {
		t.Fatalf("allowed %d from one IP, want burst %d", allowed, cfg.IPBurst*2)
	}
	if !l.allow(httptest.NewRecorder(), req("198.51.100.4"), BucketInternalIP, "") {
		t.Fatal("a different client IP was limited")
	}
	// The account-only internal bucket never limits by IP (the IRC server's
	// own address is shared by everyone when nothing is forwarded).
	if b := l.buckets[BucketInternal]; b.ip != nil {
		t.Fatal("BucketInternal must not have a per-IP limiter")
	}
}
