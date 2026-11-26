// Package bridge gives every Boson account its account on the evrd bridge
// (evrd's managed mode, docs/bridge.md) that fronts an existing IRC
// server: local, NickServ and federated accounts alike.
//
//   - Changes to users (created, renamed, email, display name, disabled,
//     deleted) are queued by database triggers in bridge_outbox, in the
//     changing transaction, and pushed by Run with retries and backoff.
//   - A full sync (Reconcile) at startup, every BRIDGE_RECONCILE_INTERVAL
//     and on POST /internal/v1/bridge/reconcile makes the bridge's accounts
//     match auth's, removing bridge accounts no Boson account has.
//   - After each NickServ sign-in, AccountSignedIn hands the bridge the
//     services login (the NickServ password), so the bridge can log the
//     user in to NickServ. The password is only ever held in memory while
//     it's being sent; it's never logged or stored.
package bridge

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/metrics"
	"github.com/rs/zerolog"
)

// ErrReconcileRunning: another full sync (maybe on another replica) is running.
var ErrReconcileRunning = apperr.New(http.StatusConflict, "reconcile_running", "a full sync of the bridge's accounts is already running")

// DefaultCredentialRetries are the waits between attempts to hand the
// bridge a NickServ login (about two minutes in all). After that the
// login is dropped from memory; the next sign-in sends it again.
var DefaultCredentialRetries = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute}

// claimBatch is how many users' changes one Claim takes.
const claimBatch = 10

// reconcileLease bounds a full sync that died with its replica.
const reconcileLease = 10 * time.Minute

type Deps struct {
	Client  Client
	Store   Store
	Metrics *metrics.Metrics
	Config  config.BridgeConfig
	// Strategy is NICKSERV_STRATEGY (picks the default login method).
	Strategy string
	// Log: nil logs with the base logger.
	Log *zerolog.Logger
	// CredentialRetries: nil is DefaultCredentialRetries.
	CredentialRetries []time.Duration
}

// Result is what a full sync did.
type Result struct {
	Users     int `json:"users"`
	Put       int `json:"put"`
	Deleted   int `json:"deleted"`
	Unchanged int `json:"unchanged"`
	// Skipped: accounts whose username the bridge can't use.
	Skipped int `json:"skipped"`
	Failed  int `json:"failed"`
}

type Service struct {
	Deps
	method string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	inflight map[string]*push // user id → its NickServ login push
}

type push struct{ cancel context.CancelFunc }

// New builds the service; Run starts its work.
func New(d Deps) *Service {
	if d.Metrics == nil {
		d.Metrics = metrics.Noop()
	}
	if d.CredentialRetries == nil {
		d.CredentialRetries = DefaultCredentialRetries
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{Deps: d, method: d.Config.Method(d.Strategy), ctx: ctx, cancel: cancel, inflight: map[string]*push{}}
}

func (s *Service) log() *zerolog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return logger.FromCtx(s.ctx)
}

// Method is the login method NickServ accounts get on the bridge.
func (s *Service) Method() string { return s.method }

// Start turns the outbox on. Call before serving requests.
func (s *Service) Start(ctx context.Context) error {
	if err := s.Store.SetEnabled(ctx, true); err != nil {
		return err
	}
	return s.Metrics.ObserveBridgeOutbox(s.Store.Pending)
}

// Run pushes queued changes every BRIDGE_POLL_INTERVAL and runs a full
// sync at once and every BRIDGE_RECONCILE_INTERVAL, until ctx is done.
func (s *Service) Run(ctx context.Context) {
	s.reconcileLogged(ctx)
	poll := time.NewTicker(s.Config.PollInterval)
	defer poll.Stop()
	var full <-chan time.Time
	if s.Config.ReconcileInterval > 0 {
		t := time.NewTicker(s.Config.ReconcileInterval)
		defer t.Stop()
		full = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			if _, err := s.Drain(ctx); err != nil && ctx.Err() == nil {
				s.log().Warn().Err(err).Msg("bridge: reading the outbox")
			}
		case <-full:
			s.reconcileLogged(ctx)
		}
	}
}

func (s *Service) reconcileLogged(ctx context.Context) {
	res, err := s.Reconcile(ctx)
	switch {
	case errors.Is(err, ErrReconcileRunning) || ctx.Err() != nil:
	case err != nil:
		s.log().Warn().Err(err).Int("put", res.Put).Int("deleted", res.Deleted).Int("failed", res.Failed).Msg("bridge: full sync failed")
	case res.Put+res.Deleted > 0:
		s.log().Info().Int("users", res.Users).Int("put", res.Put).Int("deleted", res.Deleted).Int("skipped", res.Skipped).Msg("bridge: full sync")
	}
}

// Close stops NickServ login pushes still retrying and waits for them.
func (s *Service) Close() {
	s.cancel()
	s.wg.Wait()
}

// Wait waits for the NickServ login pushes in flight (tests).
func (s *Service) Wait() { s.wg.Wait() }

// Status is the outbox and full sync state.
func (s *Service) Status(ctx context.Context) (Status, error) { return s.Store.Status(ctx) }

func (s *Service) backoff(attempts int) time.Duration {
	d := s.Config.RetryMin
	for i := 1; i < attempts && d < s.Config.RetryMax; i++ {
		d *= 2
	}
	return min(d, s.Config.RetryMax)
}

// Drain pushes every due change once; returns how many users it pushed.
func (s *Service) Drain(ctx context.Context) (int, error) {
	done := 0
	// Long enough for the batch (up to four calls per user); a replica that
	// dies mid-batch leaves the rest to the others after it.
	lease := claimBatch*4*s.Config.Timeout + 30*time.Second
	for ctx.Err() == nil {
		changes, err := s.Store.Claim(ctx, claimBatch, lease)
		if err != nil || len(changes) == 0 {
			return done, err
		}
		byUser := map[string][]Change{}
		var order []string
		for _, c := range changes {
			if _, ok := byUser[c.UserID]; !ok {
				order = append(order, c.UserID)
			}
			byUser[c.UserID] = append(byUser[c.UserID], c)
		}
		for _, uid := range order {
			cs := byUser[uid]
			ids := make([]int64, len(cs))
			names := make([]string, len(cs))
			attempts := 0
			for i, c := range cs {
				ids[i], names[i] = c.ID, c.Username
				attempts = max(attempts, c.Attempts)
			}
			if err := s.apply(ctx, uid, names); err != nil {
				if ctx.Err() != nil {
					return done, ctx.Err()
				}
				s.log().Warn().Err(err).Str("user_id", uid).Int("attempts", attempts+1).
					Dur("retry_in", s.backoff(attempts+1)).Msg("bridge: push failed, will retry")
				if rerr := s.Store.Retry(ctx, ids, err.Error(), s.backoff); rerr != nil {
					return done, rerr
				}
				continue
			}
			if err := s.Store.Done(ctx, ids); err != nil {
				return done, err
			}
			done++
		}
	}
	return done, ctx.Err()
}

// apply makes the bridge match user uid now: its account under its
// current name, and none under oldNames.
func (s *Service) apply(ctx context.Context, uid string, oldNames []string) error {
	u, err := s.Store.User(ctx, uid)
	if err != nil {
		return err
	}
	cur := ""
	if u != nil {
		var ok bool
		if cur, ok = Name(u.Username); !ok {
			s.log().Info().Str("user_id", uid).Str("username", u.Username).Msg("bridge: skipping an account the bridge can't name")
		}
	}
	seen := map[string]bool{cur: true}
	for _, old := range oldNames {
		n, ok := Name(old)
		if !ok || seen[n] {
			continue
		}
		seen[n] = true
		if err := s.deleteOwned(ctx, n, uid); err != nil {
			return err
		}
	}
	if u == nil || cur == "" {
		return nil
	}
	return s.putUser(ctx, *u, cur, nil)
}

// deleteOwned removes bridge account name if it's uid's (by subject): a
// name can belong to another, newer account by now.
func (s *Service) deleteOwned(ctx context.Context, name, uid string) error {
	a, err := s.Client.Get(ctx, name)
	if err != nil {
		return err
	}
	if a == nil || a.Subject != uid {
		return nil
	}
	return s.delete(ctx, name, uid)
}

func (s *Service) delete(ctx context.Context, name, uid string) error {
	if err := s.Client.Delete(ctx, name); err != nil {
		s.Metrics.BridgePush(ctx, metrics.BridgeOpDelete, metrics.OutcomeError)
		return err
	}
	s.Metrics.BridgePush(ctx, metrics.BridgeOpDelete, metrics.OutcomeSuccess)
	s.log().Info().Str("user_id", uid).Str("bridge_user", name).Msg("bridge: account removed")
	return nil
}

// putUser makes bridge account name u's, with login (nil: the services
// login is left alone, or set to none for an account without NickServ).
func (s *Service) putUser(ctx context.Context, u User, name string, login *Auth) error {
	op := metrics.BridgeOpPut
	if login != nil {
		op = metrics.BridgeOpCredentials
	}
	cur, err := s.Client.Get(ctx, name)
	if err != nil {
		s.Metrics.BridgePush(ctx, op, metrics.OutcomeError)
		return err
	}
	b := body(u, cur)
	if login != nil {
		w := Want(u)
		w.Auth = login
		b = &w
	}
	if b == nil {
		return nil
	}
	err = s.Client.Put(ctx, name, *b)
	if IsStatus(err, http.StatusConflict) {
		// The subject is on another bridge account: u's old name (a rename
		// the outbox hasn't pushed yet). That one goes first.
		if err = s.dropSubjectElsewhere(ctx, u.ID, name); err == nil {
			err = s.Client.Put(ctx, name, *b)
		}
	}
	if err != nil {
		s.Metrics.BridgePush(ctx, op, metrics.OutcomeError)
		return err
	}
	s.Metrics.BridgePush(ctx, op, metrics.OutcomeSuccess)
	ev := s.log().Debug()
	if cur == nil {
		ev = s.log().Info()
	}
	ev.Str("user_id", u.ID).Str("bridge_user", name).Bool("created", cur == nil).Bool("disabled", u.Disabled).
		Bool("login", login != nil).Msg("bridge: account up to date")
	return nil
}

func (s *Service) dropSubjectElsewhere(ctx context.Context, uid, keep string) error {
	all, err := s.Client.List(ctx)
	if err != nil {
		return err
	}
	for _, a := range all {
		if a.Subject == uid && !strings.EqualFold(a.Username, keep) {
			if err := s.delete(ctx, strings.ToLower(a.Username), uid); err != nil {
				return err
			}
		}
	}
	return nil
}

// Reconcile makes the bridge's accounts match auth's: every account with
// a name the bridge can use, and no others.
func (s *Service) Reconcile(ctx context.Context) (Result, error) {
	var res Result
	ok, err := s.Store.LeaseReconcile(ctx, reconcileLease)
	if err != nil {
		return res, err
	}
	if !ok {
		return res, ErrReconcileRunning
	}
	err = s.reconcile(ctx, &res)
	outcome, text := metrics.OutcomeSuccess, ""
	if err != nil {
		outcome, text = metrics.OutcomeError, err.Error()
	}
	s.Metrics.BridgePush(ctx, metrics.BridgeOpReconcile, outcome)
	// A full sync stopped by shutdown still gives the lease back.
	if derr := s.Store.ReconcileDone(context.WithoutCancel(ctx), text); derr != nil && err == nil {
		err = derr
	}
	return res, err
}

func (s *Service) reconcile(ctx context.Context, res *Result) error {
	// The bridge first: an account the outbox creates after this listing
	// isn't in it, so it can't be taken for one nobody has.
	have, err := s.Client.List(ctx)
	if err != nil {
		return err
	}
	users, err := s.Store.Users(ctx)
	if err != nil {
		return err
	}
	res.Users = len(users)
	byName := map[string]*Account{}
	bySubject := map[string]*Account{}
	for i := range have {
		a := &have[i]
		byName[strings.ToLower(a.Username)] = a
		if a.Subject != "" {
			bySubject[a.Subject] = a
		}
	}
	var firstErr error
	note := func(err error) bool {
		if err != nil {
			res.Failed++
			if firstErr == nil {
				firstErr = err
			}
		}
		return err != nil
	}
	wanted := map[string]bool{}
	for _, u := range users {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name, ok := Name(u.Username)
		if !ok {
			res.Skipped++
			continue
		}
		wanted[name] = true
		// Renamed in Boson: the old bridge account goes first (a subject
		// belongs to one account).
		if old, ok := bySubject[u.ID]; ok && !strings.EqualFold(old.Username, name) {
			if note(s.delete(ctx, strings.ToLower(old.Username), u.ID)) {
				continue
			}
			res.Deleted++
			delete(byName, strings.ToLower(old.Username))
		}
		b := body(u, byName[name])
		if b == nil {
			res.Unchanged++
			continue
		}
		err := s.Client.Put(ctx, name, *b)
		if note(err) {
			s.Metrics.BridgePush(ctx, metrics.BridgeOpPut, metrics.OutcomeError)
			continue
		}
		s.Metrics.BridgePush(ctx, metrics.BridgeOpPut, metrics.OutcomeSuccess)
		res.Put++
	}
	var gone []string
	for name := range byName {
		if !wanted[name] {
			gone = append(gone, name)
		}
	}
	sort.Strings(gone)
	for _, name := range gone {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !note(s.delete(ctx, name, byName[name].Subject)) {
			res.Deleted++
		}
	}
	return firstErr
}

// AccountSignedIn implements nsaccount.Provisioner: after each NickServ
// sign-in it hands the bridge the account with its services login, so
// password changes reach the bridge too. It returns at once; the push
// runs in the background (retried for a while if the bridge is down).
func (s *Service) AccountSignedIn(_ context.Context, u *user.User, account, password string) error {
	name, ok := Name(u.Username)
	if !ok {
		s.log().Info().Str("user_id", u.ID).Str("username", u.Username).Msg("bridge: skipping an account the bridge can't name")
		return nil
	}
	usr := User{ID: u.ID, Username: u.Username, Email: u.EmailOrEmpty(), DisplayName: u.DisplayName,
		Disabled: u.Disabled(), NickServAccount: account}
	login := &Auth{Method: s.method, Account: account, Password: password}

	ctx, cancel := context.WithCancel(s.ctx)
	p := &push{cancel: cancel}
	s.mu.Lock()
	if old := s.inflight[u.ID]; old != nil {
		old.cancel() // a newer sign-in: its password wins
	}
	s.inflight[u.ID] = p
	s.wg.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			if s.inflight[usr.ID] == p {
				delete(s.inflight, usr.ID)
			}
			s.mu.Unlock()
			cancel()
		}()
		for attempt := 0; ; attempt++ {
			cctx, ccancel := context.WithTimeout(ctx, s.Config.Timeout)
			err := s.putUser(cctx, usr, name, login)
			ccancel()
			if err == nil || ctx.Err() != nil {
				return
			}
			if attempt >= len(s.CredentialRetries) {
				s.Metrics.BridgePush(ctx, metrics.BridgeOpCredentials, metrics.OutcomeDropped)
				s.log().Warn().Err(err).Str("user_id", usr.ID).Str("bridge_user", name).
					Msg("bridge: couldn't hand the bridge the NickServ login; the next sign-in sends it again")
				return
			}
			s.log().Warn().Err(err).Str("user_id", usr.ID).Str("bridge_user", name).Int("attempt", attempt+1).
				Msg("bridge: handing the bridge the NickServ login failed, will retry")
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.CredentialRetries[attempt]):
			}
		}
	}()
	return nil
}
