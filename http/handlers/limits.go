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
	// SSO browser endpoints (start, callback, ACS) and the code exchange; per IP.
	BucketSSO         = "sso"
	BucketSSOExchange = "sso_exchange"
	BucketInternal    = "internal"
	// BucketInternalIP limits internal password checks per end-user IP, as
	// forwarded by the (token-authenticated) caller. Only applied when the
	// caller forwards one, so the IRC server's own address is never limited.
	BucketInternalIP = "internal_ip"
	// BucketPublic limits the unauthenticated, cacheable lookups
	// (GET /v1/roles, GET /v1/users/roles) per IP.
	BucketPublic = "public"
	// BucketGuestVoice limits POST /v1/voice/guest-token per client IP.
	BucketGuestVoice = "guest_voice"
	// BucketEmailTest limits POST /internal/email/test per admin.
	BucketEmailTest = "email_test"
	// BucketEmailPreview limits POST /internal/email/preview per admin.
	BucketEmailPreview = "email_preview"
)

// Test emails per admin: a burst of 5, then one every 6 minutes.
const (
	emailTestBurst     = 5
	emailTestPerMinute = 1.0 / 6
)

// Guest voice tokens per client IP: a burst of 20, then 20 a minute
// (a token lasts VOICE_TOKEN_TTL; clients fetch one per join).
const (
	guestVoiceBurst     = 20
	guestVoicePerMinute = 20
)

// Previews per admin: the panel previews on every (debounced) keystroke,
// so a burst of 60, refilled at 5 a second.
const (
	emailPreviewBurst     = 60
	emailPreviewPerMinute = 300
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
	for _, b := range []string{BucketLogin, BucketRegister, BucketForgot, BucketReset, BucketVerify, BucketSSO, BucketSSOExchange} {
		l.buckets[b] = bucketPair{
			ip:      ratelimit.New(cfg.IPBurst, cfg.IPPerMinute),
			account: ratelimit.New(cfg.AccountBurst, cfg.AccountPerMinute),
		}
	}
	// The internal caller is the IRC server: one IP for every user, so only
	// per-account limits apply, with a larger burst for reconnect storms.
	l.buckets[BucketInternal] = bucketPair{account: ratelimit.New(cfg.AccountBurst*2, cfg.AccountPerMinute*2)}
	// Per forwarded client IP: catches one IRC client trying many accounts.
	l.buckets[BucketInternalIP] = bucketPair{ip: ratelimit.New(cfg.IPBurst*2, cfg.IPPerMinute*2)}
	pubBurst, pubRate := cfg.PublicBurst, cfg.PublicPerMinute
	if pubBurst <= 0 || pubRate <= 0 { // unset (struct literal): scale the IP limits
		pubBurst, pubRate = cfg.IPBurst*3, cfg.IPPerMinute*12
	}
	l.buckets[BucketPublic] = bucketPair{ip: ratelimit.New(pubBurst, pubRate)}
	l.buckets[BucketGuestVoice] = bucketPair{ip: ratelimit.New(guestVoiceBurst, guestVoicePerMinute)}
	l.buckets[BucketEmailTest] = bucketPair{account: ratelimit.New(emailTestBurst, emailTestPerMinute)}
	l.buckets[BucketEmailPreview] = bucketPair{account: ratelimit.New(emailPreviewBurst, emailPreviewPerMinute)}
	return l
}

// RunPruner drops idle buckets until ctx is done.
func (l *Limits) RunPruner(ctx context.Context) { l.runPruners(ctx, time.Minute) }

func (l *Limits) runPruners(ctx context.Context, every time.Duration) {
	for _, b := range l.buckets {
		// Either side may be absent (internal: account only; internal_ip: IP only).
		if b.ip != nil {
			go b.ip.RunPruner(ctx, every)
		}
		if b.account != nil {
			go b.account.RunPruner(ctx, every)
		}
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
