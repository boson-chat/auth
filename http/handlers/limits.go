package handlers

import (
	"context"
	"math"
	nethttp "net/http"
	"strconv"
	"strings"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/ratelimit"
	"github.com/boson-chat/auth/internal/reqmeta"
	"github.com/boson-chat/auth/metrics"
)

// Rate-limit buckets.
const (
	BucketLogin    = "login"
	BucketRegister = "register"
	BucketForgot   = "forgot"
	BucketReset    = "reset"
	BucketVerify   = "verify"
	BucketInternal = "internal"
)

type bucketPair struct {
	ip, account *ratelimit.Limiter
}

// Limits holds the per-IP and per-account limiters for each bucket.
type Limits struct {
	enabled bool
	buckets map[string]bucketPair
	metrics *metrics.Metrics
}

func NewLimits(cfg config.RateLimitConfig, m *metrics.Metrics) *Limits {
	l := &Limits{enabled: cfg.Enabled, buckets: map[string]bucketPair{}, metrics: m}
	for _, b := range []string{BucketLogin, BucketRegister, BucketForgot, BucketReset, BucketVerify} {
		l.buckets[b] = bucketPair{
			ip:      ratelimit.New(cfg.IPBurst, cfg.IPPerMinute),
			account: ratelimit.New(cfg.AccountBurst, cfg.AccountPerMinute),
		}
	}
	// The internal caller is the IRC server: one IP for every user, so only
	// per-account limits apply, with a larger burst for reconnect storms.
	l.buckets[BucketInternal] = bucketPair{account: ratelimit.New(cfg.AccountBurst*2, cfg.AccountPerMinute*2)}
	return l
}

// RunPruner drops idle buckets until ctx is done.
func (l *Limits) RunPruner(ctx context.Context) {
	for _, b := range l.buckets {
		if b.ip != nil {
			go b.ip.RunPruner(ctx, time.Minute)
		}
		go b.account.RunPruner(ctx, time.Minute)
	}
}

var errRateLimited = apperr.New(nethttp.StatusTooManyRequests, "rate_limited", "too many requests, try again later")

// allow checks the IP and (if account != "") account buckets. On denial it
// writes the 429 with Retry-After and returns false.
func (l *Limits) allow(w nethttp.ResponseWriter, r *nethttp.Request, bucket, account string) bool {
	if !l.enabled {
		return true
	}
	b := l.buckets[bucket]
	var wait time.Duration
	ok := true
	if b.ip != nil {
		ok, wait = b.ip.Allow(reqmeta.From(r.Context()).IP)
	}
	if ok && account != "" {
		ok, wait = b.account.Allow(account)
	}
	if ok {
		return true
	}
	l.metrics.RateLimited(r.Context(), bucket)
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(max(wait.Seconds(), 1)))))
	writeError(w, r, errRateLimited)
	return false
}

// accountKey normalises a login identifier so case variants share a bucket.
func accountKey(login string) string {
	login = strings.TrimSpace(login)
	if strings.Contains(login, "@") {
		return "e:" + strings.ToLower(login)
	}
	return "u:" + nick.Fold(login)
}
