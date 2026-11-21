// Package rolechannels is Discord-style channel access for network roles:
// admins attach IRC channels to roles (and to "everyone", the built-in
// Member role) and mark channels private. RoleServ (the stack's Ergo
// helper) enforces it: a private channel is +i with an account invite
// exception for every member of a role that lists it, and, when
// roles.channels.autojoin is on, members are joined to their roles'
// channels at login and when they gain a role.
package rolechannels

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/db"
	"github.com/boson-chat/auth/internal/db/repositories"
	"github.com/boson-chat/auth/internal/db/repositories/role"
	"github.com/boson-chat/auth/internal/db/repositories/rolechannel"
	"github.com/boson-chat/auth/internal/db/repositories/user"
	"github.com/boson-chat/auth/internal/ids"
	"github.com/boson-chat/auth/internal/nick"
	"github.com/boson-chat/auth/internal/perm"
	"github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/services/roles"
	"github.com/boson-chat/auth/internal/textutil"
)

const (
	// Everyone is the role id the API accepts for the built-in Member role.
	Everyone = "everyone"
	// EveryoneName is how the Member role shows in via lists.
	EveryoneName = "Everyone"
	// MaxChannelLen is Ergo's default channel length limit (channellen).
	MaxChannelLen = config.MaxChannelNameLen
	// MaxRoleChannels bounds one role's channel list.
	MaxRoleChannels = 100
	// MaxPrivate bounds the private channel list.
	MaxPrivate = 500
)

// Settings are roles.channels and the irc: network channel keys in the
// stack config file.
type Settings struct {
	Autojoin bool
	Rejoin   string
	// Network is irc.channels, irc.channel_founder and irc.autojoin_guests.
	Network NetworkSettings
}

// NetworkSettings are the network channels (config irc:).
type NetworkSettings struct {
	Channels []config.NetworkChannel
	// Founder is irc.channel_founder ("" = the earliest-assigned Owner).
	Founder        string
	AutojoinGuests bool
}

// fingerprint is the settings' part of the feed version. The resolved
// founder needs no part of it: owner assignments, renames and disabling
// all bump the grants version.
func (s Settings) fingerprint() string {
	a := "0"
	if s.Autojoin {
		a = "1"
	}
	if n := s.Network; len(n.Channels) > 0 || n.Founder != "" || !n.AutojoinGuests {
		h := sha256.New()
		fmt.Fprintf(h, "%q %t", n.Founder, n.AutojoinGuests)
		for _, c := range n.Channels {
			fmt.Fprintf(h, " %q %q %t", c.Name, c.Topic, c.Autojoin)
		}
		return a + s.Rejoin + "." + hex.EncodeToString(h.Sum(nil))[:16]
	}
	return a + s.Rejoin
}

// networkAutojoin are the folded auto-join network channels, sorted.
func (n NetworkSettings) networkAutojoin() []string {
	out := []string{}
	for _, c := range n.Channels {
		if f := c.Folded(); c.Autojoin && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	slices.Sort(out)
	return out
}

// NormalizeChannel validates an IRC channel name and folds it the way Ergo
// (casemapping: ascii) does: #, then 1..63 printable ASCII characters
// other than space and comma, lower-cased.
func NormalizeChannel(s string) (string, error) {
	s = strings.TrimSpace(s)
	if msg := config.CheckChannelName(s); msg != "" {
		return "", apperr.Invalid(msg)
	}
	return strings.ToLower(s), nil
}

// ChannelInput is one entry of PUT /v1/admin/roles/{id}/channels.
type ChannelInput struct {
	Channel string `json:"channel"`
	// Autojoin defaults to true.
	Autojoin *bool `json:"autojoin"`
}

// AccessInput is one entry of PUT /v1/admin/channel-access.
type AccessInput struct {
	Channel string `json:"channel"`
	Private bool   `json:"private"`
}

// RoleChannel is a channel of a role.
type RoleChannel struct {
	Channel  string `json:"channel"`
	Autojoin bool   `json:"autojoin"`
	Private  bool   `json:"private"`
}

// RoleRef names a role.
type RoleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Autojoin is whether this role auto-joins the channel.
	Autojoin bool `json:"autojoin"`
}

// ChannelAccess is one channel of GET /v1/admin/channel-access: every
// channel listed on a role or marked private.
type ChannelAccess struct {
	Channel string    `json:"channel"`
	Private bool      `json:"private"`
	Roles   []RoleRef `json:"roles"`
}

// FeedChannel is one channel of GET /internal/v1/irc/channel-access.
type FeedChannel struct {
	Channel string `json:"channel"`
	Private bool   `json:"private"`
	// Everyone: the channel is listed on the Member role, so every account
	// may join (Accounts is then empty; RoleServ makes it +R, not +i).
	Everyone bool `json:"everyone"`
	// Accounts are the Ergo-casefolded (ASCII lower-case) names of the
	// enabled accounts that may join a private channel.
	Accounts []string `json:"accounts"`
}

// Feed is GET /internal/v1/irc/channel-access.
type Feed struct {
	Version  string        `json:"version"`
	Autojoin bool          `json:"autojoin"`
	Rejoin   string        `json:"rejoin"`
	Channels []FeedChannel `json:"channels"`
	// Network are the network channels RoleServ keeps created and
	// registered (config irc.channels).
	Network FeedNetwork `json:"network"`
}

// FeedNetwork is the network part of the feed.
type FeedNetwork struct {
	// Founder is irc.channel_founder, else the username of the enabled
	// account that has held the Owner role longest, else "" (RoleServ's
	// own account).
	Founder        string               `json:"founder"`
	AutojoinGuests bool                 `json:"autojoin_guests"`
	Channels       []FeedNetworkChannel `json:"channels"`
}

// FeedNetworkChannel is one network channel.
type FeedNetworkChannel struct {
	// Channel is the folded name, Name as written in the config.
	Channel  string `json:"channel"`
	Name     string `json:"name"`
	Topic    string `json:"topic"`
	Autojoin bool   `json:"autojoin"`
}

// Autojoin is GET /internal/v1/irc/autojoin for one account.
type Autojoin struct {
	Account string `json:"account"`
	// Enabled is roles.channels.autojoin.
	Enabled bool   `json:"enabled"`
	Rejoin  string `json:"rejoin"`
	// Channels are every channel the account's roles (and everyone's)
	// auto-join, sorted.
	Channels []string `json:"channels"`
	// Pending are the Channels RoleServ hasn't auto-joined the account to
	// yet (rejoin: once joins only these).
	Pending []string `json:"pending"`
	// Network are the auto-join network channels (folded, sorted); they are
	// always joined once, whatever Enabled and Rejoin say.
	Network []string `json:"network"`
	// NetworkPending are the Network channels not yet auto-joined.
	NetworkPending []string `json:"network_pending"`
}

// MyChannel is one entry of GET /v1/me/channels.
type MyChannel struct {
	Channel  string `json:"channel"`
	Private  bool   `json:"private"`
	Autojoin bool   `json:"autojoin"`
	// Via are the names of the roles that give the channel ("Everyone" for
	// the Member role), most senior first.
	Via []string `json:"via"`
}

type RoleChannelsServiceImpl interface {
	// ForRole lists a role's channels ("everyone" = Member).
	ForRole(ctx context.Context, roleID string) (string, []RoleChannel, error)
	// SetForRole replaces a role's channels (roles.manage, and the role
	// must be below the actor's highest role).
	SetForRole(ctx context.Context, actorID, roleID string, in []ChannelInput) (string, []RoleChannel, error)
	// Access lists every channel listed on a role or marked private.
	Access(ctx context.Context) ([]ChannelAccess, error)
	// SetAccess makes the channels with private true the private ones.
	SetAccess(ctx context.Context, actorID string, in []AccessInput) ([]ChannelAccess, error)
	// FeedVersion changes whenever Feed or any account's Autojoin may have.
	FeedVersion(ctx context.Context) (string, error)
	Feed(ctx context.Context) (*Feed, error)
	// Autojoin is one account's auto-join channels (by account name).
	Autojoin(ctx context.Context, account string) (*Autojoin, error)
	// RecordAutojoined notes that RoleServ joined account to channels
	// (only channels the account still gets are kept).
	RecordAutojoined(ctx context.Context, account string, channels []string) (*Autojoin, error)
	// ForUser is GET /v1/me/channels.
	ForUser(ctx context.Context, userID string) ([]MyChannel, error)
}

type Deps struct {
	Channels rolechannel.RoleChannelRepositoryImpl
	Roles    role.RoleRepositoryImpl
	Users    user.UserRepositoryImpl
	// Access is the actor's permissions (roles service).
	Access func(ctx context.Context, userID string) (*roles.Access, error)
	Tx     db.TxManagerImpl
	Audit  audit.AuditServiceImpl
	// Settings returns roles.channels now (hot-reloaded config).
	Settings func() Settings
	Now      func() time.Time
}

type RoleChannelsService struct {
	d Deps
}

func NewRoleChannelsService(d Deps) RoleChannelsServiceImpl {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Settings == nil {
		d.Settings = func() Settings {
			return Settings{Rejoin: config.RejoinLogin, Network: NetworkSettings{AutojoinGuests: true}}
		}
	}
	return &RoleChannelsService{d: d}
}

func (s *RoleChannelsService) settings() Settings {
	st := s.d.Settings()
	if !config.ValidRejoin(st.Rejoin) {
		st.Rejoin = config.RejoinLogin
	}
	return st
}

func notFound(err error) error {
	if errors.Is(err, repositories.ErrNotFound) {
		return apperr.ErrNotFound
	}
	return err
}

// roleID maps "everyone" to the Member role and checks the id's shape.
func roleID(id string) (string, bool) {
	if strings.EqualFold(id, Everyone) {
		return role.MemberID, true
	}
	return id, textutil.Storable(id) && ids.HasPrefix(id, ids.Role)
}

func (s *RoleChannelsService) findRole(ctx context.Context, id string) (*role.Role, error) {
	rid, ok := roleID(id)
	if !ok {
		return nil, apperr.ErrNotFound
	}
	r, err := s.d.Roles.FindByID(ctx, rid)
	return r, notFound(err)
}

// apiID is the role id the API shows: "everyone" for Member.
func apiID(id string) string {
	if id == role.MemberID {
		return Everyone
	}
	return id
}

func viaName(r *role.Role) string {
	if r.Is(role.BuiltinMember) {
		return EveryoneName
	}
	return r.Name
}

func (s *RoleChannelsService) privateSet(ctx context.Context) (map[string]bool, error) {
	list, err := s.d.Channels.Private(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(list))
	for _, a := range list {
		out[a.Channel] = true
	}
	return out, nil
}

func (s *RoleChannelsService) roleChannels(ctx context.Context, roleID string) ([]RoleChannel, error) {
	list, err := s.d.Channels.ForRoles(ctx, []string{roleID})
	if err != nil {
		return nil, err
	}
	private, err := s.privateSet(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]RoleChannel, 0, len(list))
	for _, c := range list {
		out = append(out, RoleChannel{Channel: c.Channel, Autojoin: c.Autojoin, Private: private[c.Channel]})
	}
	return out, nil
}

func (s *RoleChannelsService) ForRole(ctx context.Context, id string) (string, []RoleChannel, error) {
	r, err := s.findRole(ctx, id)
	if err != nil {
		return "", nil, err
	}
	out, err := s.roleChannels(ctx, r.ID)
	return apiID(r.ID), out, err
}

func (s *RoleChannelsService) actor(ctx context.Context, actorID string) (*roles.Access, error) {
	a, err := s.d.Access(ctx, actorID)
	if err != nil {
		return nil, err
	}
	if !a.Has(perm.RolesManage) {
		return nil, apperr.ErrForbidden
	}
	return a, nil
}

func (s *RoleChannelsService) SetForRole(ctx context.Context, actorID, id string, in []ChannelInput) (string, []RoleChannel, error) {
	if len(in) > MaxRoleChannels {
		return "", nil, apperr.Invalid(fmt.Sprintf("a role can list at most %d channels", MaxRoleChannels))
	}
	want := make([]*rolechannel.RoleChannel, 0, len(in))
	seen := map[string]bool{}
	now := s.d.Now().UTC()
	for _, c := range in {
		ch, err := NormalizeChannel(c.Channel)
		if err != nil {
			return "", nil, err
		}
		if seen[ch] {
			return "", nil, apperr.Invalid("channel " + ch + " is listed twice")
		}
		seen[ch] = true
		autojoin := c.Autojoin == nil || *c.Autojoin
		want = append(want, &rolechannel.RoleChannel{Channel: ch, Autojoin: autojoin, CreatedAt: now})
	}
	var r *role.Role
	var before []*rolechannel.RoleChannel
	err := s.d.Tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.d.Roles.Lock(ctx); err != nil {
			return err
		}
		var err error
		if r, err = s.findRole(ctx, id); err != nil {
			return err
		}
		a, err := s.actor(ctx, actorID)
		if err != nil {
			return err
		}
		if !a.CanManageRole(r) {
			return roles.ErrHierarchy
		}
		if before, err = s.d.Channels.ForRoles(ctx, []string{r.ID}); err != nil {
			return err
		}
		for _, c := range want {
			c.RoleID = r.ID
		}
		return s.d.Channels.ReplaceForRole(ctx, r.ID, want)
	})
	if err != nil {
		return "", nil, err
	}
	old := map[string]bool{}
	oldList := map[string]any{}
	for _, c := range before {
		old[c.Channel] = c.Autojoin
		oldList[c.Channel] = map[string]any{"autojoin": c.Autojoin}
	}
	var added, removed []string
	newList := map[string]any{}
	changed := false
	for _, c := range want {
		newList[c.Channel] = map[string]any{"autojoin": c.Autojoin}
		if aj, ok := old[c.Channel]; !ok {
			added = append(added, c.Channel)
		} else if aj != c.Autojoin {
			changed = true
		}
	}
	for _, c := range before {
		if !seen[c.Channel] {
			removed = append(removed, c.Channel)
		}
	}
	if changed || len(added)+len(removed) > 0 {
		s.d.Audit.Record(ctx, actorID, audit.EventRoleChannelsUpdated, map[string]any{
			"role_id": apiID(r.ID), "name": r.Name, "old": oldList, "new": newList, "added": nonNil(added), "removed": nonNil(removed),
		})
	}
	out, err := s.roleChannels(ctx, r.ID)
	return apiID(r.ID), out, err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *RoleChannelsService) Access(ctx context.Context) ([]ChannelAccess, error) {
	all, err := s.d.Channels.All(ctx)
	if err != nil {
		return nil, err
	}
	private, err := s.privateSet(ctx)
	if err != nil {
		return nil, err
	}
	rs, err := s.d.Roles.List(ctx) // most senior first
	if err != nil {
		return nil, err
	}
	rank := map[string]int{}
	byID := map[string]*role.Role{}
	for i, r := range rs {
		rank[r.ID], byID[r.ID] = i, r
	}
	byChannel := map[string][]*rolechannel.RoleChannel{}
	for _, c := range all {
		byChannel[c.Channel] = append(byChannel[c.Channel], c)
	}
	names := make([]string, 0, len(byChannel)+len(private))
	for ch := range byChannel {
		names = append(names, ch)
	}
	for ch := range private {
		if _, ok := byChannel[ch]; !ok {
			names = append(names, ch)
		}
	}
	slices.Sort(names)
	out := make([]ChannelAccess, 0, len(names))
	for _, ch := range names {
		list := byChannel[ch]
		slices.SortFunc(list, func(a, b *rolechannel.RoleChannel) int { return rank[a.RoleID] - rank[b.RoleID] })
		refs := make([]RoleRef, 0, len(list))
		for _, c := range list {
			if r, ok := byID[c.RoleID]; ok {
				refs = append(refs, RoleRef{ID: apiID(r.ID), Name: viaName(r), Autojoin: c.Autojoin})
			}
		}
		out = append(out, ChannelAccess{Channel: ch, Private: private[ch], Roles: refs})
	}
	return out, nil
}

func (s *RoleChannelsService) SetAccess(ctx context.Context, actorID string, in []AccessInput) ([]ChannelAccess, error) {
	var want []string
	seen := map[string]bool{}
	for _, c := range in {
		ch, err := NormalizeChannel(c.Channel)
		if err != nil {
			return nil, err
		}
		if seen[ch] {
			return nil, apperr.Invalid("channel " + ch + " is listed twice")
		}
		seen[ch] = true
		if c.Private {
			want = append(want, ch)
		}
	}
	if len(want) > MaxPrivate {
		return nil, apperr.Invalid(fmt.Sprintf("at most %d private channels", MaxPrivate))
	}
	slices.Sort(want)
	var before map[string]bool
	err := s.d.Tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.d.Roles.Lock(ctx); err != nil {
			return err
		}
		if _, err := s.actor(ctx, actorID); err != nil {
			return err
		}
		var err error
		if before, err = s.privateSet(ctx); err != nil {
			return err
		}
		return s.d.Channels.ReplacePrivate(ctx, want, s.d.Now().UTC())
	})
	if err != nil {
		return nil, err
	}
	var madePrivate, madePublic []string
	for _, ch := range want {
		if !before[ch] {
			madePrivate = append(madePrivate, ch)
		}
	}
	for ch := range before {
		if !slices.Contains(want, ch) {
			madePublic = append(madePublic, ch)
		}
	}
	slices.Sort(madePublic)
	if len(madePrivate)+len(madePublic) > 0 {
		s.d.Audit.Record(ctx, actorID, audit.EventChannelAccessUpdated, map[string]any{
			"private": nonNil(want), "made_private": nonNil(madePrivate), "made_public": nonNil(madePublic),
		})
	}
	return s.Access(ctx)
}

func (s *RoleChannelsService) FeedVersion(ctx context.Context) (string, error) {
	v, err := s.d.Roles.GrantsVersion(ctx)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(v, 10) + "." + s.settings().fingerprint(), nil
}

// ergoFold is Ergo's casefolding of an account name (casemapping: ascii).
func ergoFold(username string) string { return strings.ToLower(username) }

func (s *RoleChannelsService) Feed(ctx context.Context) (*Feed, error) {
	st := s.settings()
	// The version is read first: the data that follows is at least as new.
	version, err := s.FeedVersion(ctx)
	if err != nil {
		return nil, err
	}
	access, err := s.Access(ctx)
	if err != nil {
		return nil, err
	}
	// Roles listing private channels, and their enabled holders.
	var privateRoles []string
	for _, c := range access {
		if !c.Private {
			continue
		}
		for _, r := range c.Roles {
			if r.ID != Everyone && !slices.Contains(privateRoles, r.ID) {
				privateRoles = append(privateRoles, r.ID)
			}
		}
	}
	holders, err := s.d.Channels.EnabledHolders(ctx, privateRoles)
	if err != nil {
		return nil, err
	}
	byRole := map[string][]string{}
	for _, h := range holders {
		byRole[h.RoleID] = append(byRole[h.RoleID], ergoFold(h.Username))
	}
	founder := st.Network.Founder
	if founder == "" {
		if founder, err = s.d.Channels.EarliestOwner(ctx); err != nil {
			return nil, err
		}
	}
	network := FeedNetwork{Founder: founder, AutojoinGuests: st.Network.AutojoinGuests,
		Channels: make([]FeedNetworkChannel, 0, len(st.Network.Channels))}
	for _, c := range st.Network.Channels {
		network.Channels = append(network.Channels, FeedNetworkChannel{Channel: c.Folded(), Name: c.Name, Topic: c.Topic, Autojoin: c.Autojoin})
	}
	out := &Feed{Version: version, Autojoin: st.Autojoin, Rejoin: st.Rejoin, Channels: make([]FeedChannel, 0, len(access)), Network: network}
	for _, c := range access {
		fc := FeedChannel{Channel: c.Channel, Private: c.Private, Accounts: []string{}}
		if c.Private {
			set := map[string]bool{}
			for _, r := range c.Roles {
				if r.ID == Everyone {
					fc.Everyone = true
				}
				for _, a := range byRole[r.ID] {
					set[a] = true
				}
			}
			if !fc.Everyone {
				for a := range set {
					fc.Accounts = append(fc.Accounts, a)
				}
				slices.Sort(fc.Accounts)
			}
		}
		out.Channels = append(out.Channels, fc)
	}
	return out, nil
}

// userByAccount finds an account by name (RFC 1459 folding, like logins).
func (s *RoleChannelsService) userByAccount(ctx context.Context, account string) (*user.User, error) {
	account = strings.TrimSpace(account)
	if account == "" || len(account) > nick.MaxLen || !textutil.Storable(account) {
		return nil, apperr.ErrNotFound
	}
	u, err := s.d.Users.FindByUsernameFolded(ctx, nick.Fold(account))
	return u, notFound(err)
}

// autojoinChannels are the channels u's roles auto-join, sorted.
func (s *RoleChannelsService) autojoinChannels(ctx context.Context, u *user.User) ([]string, error) {
	if u.Disabled() {
		return []string{}, nil
	}
	rs, err := s.d.Roles.ForUser(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	rids := make([]string, 0, len(rs))
	for _, r := range rs {
		rids = append(rids, r.ID)
	}
	list, err := s.d.Channels.ForRoles(ctx, rids)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, c := range list {
		if c.Autojoin && !slices.Contains(out, c.Channel) {
			out = append(out, c.Channel)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (s *RoleChannelsService) autojoin(ctx context.Context, u *user.User) (*Autojoin, error) {
	st := s.settings()
	channels, err := s.autojoinChannels(ctx, u)
	if err != nil {
		return nil, err
	}
	done, err := s.d.Channels.Autojoined(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	network := []string{}
	if !u.Disabled() {
		network = st.Network.networkAutojoin()
	}
	return &Autojoin{Account: u.Username, Enabled: st.Autojoin, Rejoin: st.Rejoin, Channels: channels, Pending: notIn(channels, done),
		Network: network, NetworkPending: notIn(network, done)}, nil
}

// notIn is list without the entries in done.
func notIn(list, done []string) []string {
	out := []string{}
	for _, c := range list {
		if !slices.Contains(done, c) {
			out = append(out, c)
		}
	}
	return out
}

func (s *RoleChannelsService) Autojoin(ctx context.Context, account string) (*Autojoin, error) {
	u, err := s.userByAccount(ctx, account)
	if err != nil {
		return nil, err
	}
	return s.autojoin(ctx, u)
}

func (s *RoleChannelsService) RecordAutojoined(ctx context.Context, account string, channels []string) (*Autojoin, error) {
	if len(channels) > MaxRoleChannels*4 {
		return nil, apperr.Invalid("too many channels")
	}
	u, err := s.userByAccount(ctx, account)
	if err != nil {
		return nil, err
	}
	keep, err := s.autojoinChannels(ctx, u)
	if err != nil {
		return nil, err
	}
	// Rows of auto-join network channels are kept too (a /part sticks).
	if !u.Disabled() {
		for _, c := range s.settings().Network.networkAutojoin() {
			if !slices.Contains(keep, c) {
				keep = append(keep, c)
			}
		}
	}
	var record []string
	for _, c := range channels {
		ch, err := NormalizeChannel(c)
		if err != nil {
			return nil, err
		}
		if slices.Contains(keep, ch) && !slices.Contains(record, ch) {
			record = append(record, ch)
		}
	}
	if err := s.d.Channels.RecordAutojoined(ctx, u.ID, record, keep, s.d.Now().UTC()); err != nil {
		return nil, err
	}
	return s.autojoin(ctx, u)
}

func (s *RoleChannelsService) ForUser(ctx context.Context, userID string) ([]MyChannel, error) {
	rs, err := s.d.Roles.ForUser(ctx, userID) // most senior first
	if err != nil {
		return nil, err
	}
	rids := make([]string, 0, len(rs))
	byID := map[string]*role.Role{}
	rank := map[string]int{}
	for i, r := range rs {
		rids = append(rids, r.ID)
		byID[r.ID], rank[r.ID] = r, i
	}
	list, err := s.d.Channels.ForRoles(ctx, rids)
	if err != nil {
		return nil, err
	}
	private, err := s.privateSet(ctx)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(list, func(a, b *rolechannel.RoleChannel) int {
		if c := strings.Compare(a.Channel, b.Channel); c != 0 {
			return c
		}
		return rank[a.RoleID] - rank[b.RoleID]
	})
	out := []MyChannel{}
	for _, c := range list {
		r := byID[c.RoleID]
		if r == nil {
			continue
		}
		if n := len(out); n > 0 && out[n-1].Channel == c.Channel {
			out[n-1].Via = append(out[n-1].Via, viaName(r))
			out[n-1].Autojoin = out[n-1].Autojoin || c.Autojoin
			continue
		}
		out = append(out, MyChannel{Channel: c.Channel, Private: private[c.Channel], Autojoin: c.Autojoin, Via: []string{viaName(r)}})
	}
	return out, nil
}
