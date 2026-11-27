package bridge

import (
	"context"
	"net/http"
	"time"

	"github.com/boson-chat/auth/metrics"
)

// Settings is the body and answer of /api/managed/settings (evrd 0.61+):
// the bridge settings auth may change while evrd runs. Only Guests is
// sent; the rest are what the answer says is in effect.
type Settings struct {
	Guests                *bool    `json:"guests,omitempty"`
	GuestsMax             *int     `json:"guestsMax,omitempty"`
	GuestsPerIP           *int     `json:"guestsPerIP,omitempty"`
	GuestLingerSeconds    *int     `json:"guestLingerSeconds,omitempty"`
	NickGuardGraceSeconds *int     `json:"nickGuardGraceSeconds,omitempty"`
	Set                   []string `json:"set,omitempty"`
}

const settingsPath = "/api/managed/settings"

// guestRetryMax caps the guest setting's retry backoff: the bridge often
// starts after auth, and guests should follow soon after it does.
const guestRetryMax = time.Minute

// guestSync is the state of the push of auth's guest setting to the bridge.
type guestSync struct {
	pushed      bool // the bridge has want (as of at)
	want        bool
	at          time.Time
	failures    int
	unsupported bool // the bridge answered 404: an evrd before 0.61
}

// guestResync is how often the guest setting is sent again although it
// didn't change (the bridge's database reset, or DELETE /settings): the
// full sync's interval, or 10 minutes.
func (s *Service) guestResync() time.Duration {
	if s.Config.ReconcileInterval > 0 {
		return s.Config.ReconcileInterval
	}
	return 10 * time.Minute
}

// syncGuests sends the bridge auth's guest setting when it changed (or is
// due again) and returns the wait before the next check.
func (s *Service) syncGuests(ctx context.Context, st *guestSync, now time.Time) time.Duration {
	want, err := s.GuestAccess(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.log().Warn().Err(err).Msg("bridge: reading the guest setting")
		}
		return s.Config.PollInterval
	}
	if st.pushed && st.want == want && now.Sub(st.at) < s.guestResync() {
		return s.Config.PollInterval
	}
	cctx, cancel := context.WithTimeout(ctx, s.Config.Timeout)
	_, err = s.Client.PutSettings(cctx, Settings{Guests: &want})
	cancel()
	switch {
	case err == nil:
		s.Metrics.BridgePush(ctx, metrics.BridgeOpSettings, metrics.OutcomeSuccess)
		ev := s.log().Debug()
		if !st.pushed || st.want != want || st.failures > 0 || st.unsupported {
			ev = s.log().Info()
		}
		ev.Bool("guests", want).Msg("bridge: guest setting sent to the bridge")
		*st = guestSync{pushed: true, want: want, at: now}
		return s.Config.PollInterval
	case IsStatus(err, http.StatusNotFound):
		// An evrd without the settings API: nothing to drive. Asked again
		// at the next change or resync, so an upgraded evrd picks it up.
		if !st.unsupported {
			s.log().Info().Bool("guests", want).
				Msg("bridge: the bridge has no /api/managed/settings (evrd before 0.61); its guest setting stays as evrd.conf says")
		}
		*st = guestSync{pushed: true, want: want, at: now, unsupported: true}
		return s.Config.PollInterval
	case ctx.Err() != nil:
		return s.Config.PollInterval
	}
	s.Metrics.BridgePush(ctx, metrics.BridgeOpSettings, metrics.OutcomeError)
	st.failures++
	wait := min(s.backoff(st.failures), guestRetryMax)
	ev := s.log().Debug()
	if st.failures == 1 {
		ev = s.log().Warn()
	}
	ev.Err(err).Bool("guests", want).Int("attempts", st.failures).Dur("retry_in", wait).
		Msg("bridge: sending the guest setting failed, will retry")
	return wait
}

// RunGuests keeps the bridge's guest setting (evrd's managed_guests)
// equal to auth's guest_access until ctx is done: at once, on every
// change (checked every BRIDGE_POLL_INTERVAL) and again every
// BRIDGE_RECONCILE_INTERVAL. Without GuestAccess it returns at once.
func (s *Service) RunGuests(ctx context.Context) {
	if s.GuestAccess == nil {
		return
	}
	var st guestSync
	for {
		wait := s.syncGuests(ctx, &st, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (h *HTTPClient) PutSettings(ctx context.Context, p Settings) (*Settings, error) {
	var out Settings
	if err := h.do(ctx, http.MethodPut, settingsPath, p, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}
