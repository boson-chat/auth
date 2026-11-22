package config

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/boson-chat/auth/internal/configfile"
	"github.com/boson-chat/auth/internal/nick"
	"gopkg.in/yaml.v3"
)

// The irc: keys auth reads (network channels). The rest of irc: belongs to
// the boson-ergo helper, so auth doesn't report it as unknown.
//
//	irc:
//	  channels:                     # network channels, at most 100
//	    - name: "#lobby"
//	      topic: "Welcome to Boson" # optional, at most 300 characters
//	      autojoin: true            # default false
//	    - name: "#opers"
//	      roles: [Admin, Owner]     # optional: only these roles may join
//	  channel_founder: thelion      # optional; default: the earliest Owner
//	  autojoin_guests: true         # default true

const (
	// MaxNetworkChannels bounds irc.channels.
	MaxNetworkChannels = 100
	// MaxChannelTopicLen bounds a network channel's topic (characters).
	MaxChannelTopicLen = 300
	// MaxChannelNameLen is Ergo's default channel length limit.
	MaxChannelNameLen = 64
	// MaxChannelRoles bounds a network channel's roles list.
	MaxChannelRoles = 32
	// MaxRoleNameLen is the longest role name (auth's roles).
	MaxRoleNameLen = 32
)

// Keys of irc: in the file.
const (
	KeyIRCChannels       = "irc.channels"
	KeyIRCChannelFounder = "irc.channel_founder"
	KeyIRCAutojoinGuests = "irc.autojoin_guests"
)

// NetworkChannel is one entry of irc.channels: a fixed channel RoleServ
// keeps created and registered.
type NetworkChannel struct {
	// Name is as written in the file ("#Lobby").
	Name     string `json:"name"`
	Topic    string `json:"topic"`
	Autojoin bool   `json:"autojoin"`
	// Roles, when not empty, are the only roles whose members may join
	// (role names as written, matched case-insensitively to a role's name
	// or slug; "Member" is every account). Empty: everyone, guests too.
	Roles []string `json:"-"`
}

// Folded is the channel name as Ergo (casemapping: ascii) folds it.
func (c NetworkChannel) Folded() string { return strings.ToLower(c.Name) }

// Restricted: only some roles may join.
func (c NetworkChannel) Restricted() bool { return len(c.Roles) > 0 }

// CheckRoleName returns why s can't be a role name ("" when it can): 1..32
// letters, digits, spaces, - and _ (auth's role names).
func CheckRoleName(s string) string {
	if s == "" || len(s) > MaxRoleNameLen {
		return fmt.Sprintf("role %q must be 1-%d characters", s, MaxRoleNameLen)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ' || c == '-' || c == '_') {
			return fmt.Sprintf("role %q may only contain letters, digits, spaces, - and _", s)
		}
	}
	return ""
}

// IRCConfig is the irc: keys auth reads from the stack config file.
type IRCConfig struct {
	// Network channels (irc.channels; file only).
	Channels []NetworkChannel
	// Account that founds the network channels; "" = the earliest-assigned
	// Owner. irc.channel_founder in the file wins.
	ChannelFounder string `env:"IRC_CHANNEL_FOUNDER"`
	// Join guests and unregistered clients to the auto-join network
	// channels on connect. irc.autojoin_guests in the file wins.
	AutojoinGuests bool `default:"true" env:"IRC_AUTOJOIN_GUESTS"`
}

// CheckChannelName returns why s isn't a valid IRC channel name ("" when it
// is): #, then 1..63 printable ASCII characters other than space and comma.
func CheckChannelName(s string) string {
	if len(s) < 2 || s[0] != '#' {
		return fmt.Sprintf("channel %q must start with # and have a name", s)
	}
	if len(s) > MaxChannelNameLen {
		return fmt.Sprintf("channel %q is longer than %d characters", s, MaxChannelNameLen)
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c > '~' || c == ',' {
			return fmt.Sprintf("channel %q may only contain printable ASCII without spaces or commas", s)
		}
	}
	return ""
}

// CheckChannelTopic returns why t isn't a valid topic ("" when it is).
func CheckChannelTopic(t string) string {
	if !utf8.ValidString(t) {
		return "topic must be valid UTF-8"
	}
	if utf8.RuneCountInString(t) > MaxChannelTopicLen {
		return fmt.Sprintf("topic must be at most %d characters", MaxChannelTopicLen)
	}
	for _, r := range t {
		if unicode.IsControl(r) {
			return "topic must be one line without control characters"
		}
	}
	return ""
}

// loadIRC reads irc.channels, irc.channel_founder and irc.autojoin_guests.
func loadIRC(doc *configfile.Document, f *FileConfig) error {
	irc, err := doc.Section("irc")
	if err != nil {
		return err
	}
	items, set, err := irc.Mappings("channels")
	if err != nil {
		return err
	}
	if set {
		if len(items) > MaxNetworkChannels {
			return irc.Errorf("channels", "at most %d network channels, got %d", MaxNetworkChannels, len(items))
		}
		list := make([]NetworkChannel, 0, len(items))
		seen := map[string]bool{}
		for _, it := range items {
			name, err := it.String("name")
			if err != nil {
				return err
			}
			if name == nil {
				return it.Errorf("name", "is required (a channel such as \"#lobby\")")
			}
			n := strings.TrimSpace(*name)
			if msg := CheckChannelName(n); msg != "" {
				return it.Errorf("name", "%s", msg)
			}
			c := NetworkChannel{Name: n}
			if seen[c.Folded()] {
				return it.Errorf("name", "channel %s is listed twice", n)
			}
			seen[c.Folded()] = true
			topic, err := it.String("topic")
			if err != nil {
				return err
			}
			if topic != nil {
				c.Topic = strings.TrimSpace(*topic)
				if msg := CheckChannelTopic(c.Topic); msg != "" {
					return it.Errorf("topic", "%s", msg)
				}
			}
			aj, err := it.Bool("autojoin")
			if err != nil {
				return err
			}
			c.Autojoin = aj != nil && *aj
			var roles []string
			if n := it.Node("roles"); n != nil && !(n.Kind == yaml.ScalarNode && n.Tag == "!!null") {
				if roles, _, err = it.Strings("roles"); err != nil {
					return err
				}
			}
			if len(roles) > MaxChannelRoles {
				return it.Errorf("roles", "at most %d roles, got %d", MaxChannelRoles, len(roles))
			}
			for _, r := range roles {
				r = strings.TrimSpace(r)
				if msg := CheckRoleName(r); msg != "" {
					return it.Errorf("roles", "%s", msg)
				}
				if !slices.ContainsFunc(c.Roles, func(x string) bool { return strings.EqualFold(x, r) }) {
					c.Roles = append(c.Roles, r)
				}
			}
			f.Unknown = append(f.Unknown, it.Unknown("name", "topic", "autojoin", "roles")...)
			list = append(list, c)
		}
		f.IRCChannels, f.IRCChannelsSet = list, true
	}
	founder, err := irc.String("channel_founder")
	if err != nil {
		return err
	}
	if founder != nil {
		v := strings.TrimSpace(*founder)
		if v != "" {
			if len(v) > nick.MaxLen || !validAccountName(v) {
				return irc.Errorf("channel_founder", "must be an account name, got %q", v)
			}
		}
		f.IRCChannelFounder = &v
	}
	f.IRCAutojoinGuests, err = irc.Bool("autojoin_guests")
	return err
}

// validAccountName: an IRC nickname's characters (accounts are nicknames).
func validAccountName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("[]\\`_^{|}-", c) >= 0) {
			return false
		}
	}
	return true
}

func (f FileConfig) flattenIRC(m map[string]any) {
	if f.IRCChannelsSet {
		list := make([]any, 0, len(f.IRCChannels))
		for _, c := range f.IRCChannels {
			item := map[string]any{"name": c.Name, "topic": c.Topic, "autojoin": c.Autojoin}
			if c.Restricted() {
				roles := make([]any, 0, len(c.Roles))
				for _, r := range c.Roles {
					roles = append(roles, r)
				}
				item["roles"] = roles
			}
			list = append(list, item)
		}
		m[KeyIRCChannels] = list
	}
	if f.IRCChannelFounder != nil {
		m[KeyIRCChannelFounder] = *f.IRCChannelFounder
	}
	if f.IRCAutojoinGuests != nil {
		m[KeyIRCAutojoinGuests] = *f.IRCAutojoinGuests
	}
}

func (c Config) withIRC(f FileConfig) Config {
	if f.IRCChannelsSet {
		c.IRCConfig.Channels = append([]NetworkChannel(nil), f.IRCChannels...)
	}
	if f.IRCChannelFounder != nil {
		c.IRCConfig.ChannelFounder = *f.IRCChannelFounder
	}
	if f.IRCAutojoinGuests != nil {
		c.IRCConfig.AutojoinGuests = *f.IRCAutojoinGuests
	}
	return c
}

// exportIRC is the irc: keys for export-config: only those that differ from
// the defaults (nil when none do).
func exportIRC(c IRCConfig) []any {
	var out []any
	if len(c.Channels) > 0 {
		seq := &yaml.Node{Kind: yaml.SequenceNode}
		for _, ch := range c.Channels {
			kv := []any{"name", ch.Name}
			if ch.Topic != "" {
				kv = append(kv, "topic", ch.Topic)
			}
			kv = append(kv, "autojoin", ch.Autojoin)
			if ch.Restricted() {
				roles := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
				for _, r := range ch.Roles {
					roles.Content = append(roles.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: r})
				}
				kv = append(kv, "roles", roles)
			}
			seq.Content = append(seq.Content, mapping(kv...))
		}
		out = append(out, "channels", seq)
	}
	if c.ChannelFounder != "" {
		out = append(out, "channel_founder", c.ChannelFounder)
	}
	if !c.AutojoinGuests {
		out = append(out, "autojoin_guests", false)
	}
	return out
}
