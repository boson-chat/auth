// Package perm is the closed catalog of network role permissions.
//
// Three groups: admin (the admin API and panel), network (text/voice
// channel policies, enforced by Ergo and quicvoiced) and irc (Ergo oper
// capabilities, irc.<capability>, 1:1 with Ergo v2.19 oper-class
// capability names).
package perm

import (
	"fmt"
	"slices"
	"strings"
)

// Groups.
const (
	GroupAdmin   = "admin"
	GroupNetwork = "network"
	GroupIRC     = "irc"
)

// Admin panel / admin API.
const (
	AdminPanel      = "admin.panel"
	UsersView       = "users.view"
	UsersManage     = "users.manage"
	UsersModerate   = "users.moderate"
	InvitesManage   = "invites.manage"
	SettingsManage  = "settings.manage"
	SSOManage       = "sso.manage"
	ServicesView    = "services.view"
	ServicesManage  = "services.manage"
	AuditView       = "audit.view"
	RolesManage     = "roles.manage"
	RolesOwner      = "roles.owner"
	DirectoryManage = "directory.manage"
)

// Network (enforced by Ergo and quicvoiced).
const (
	ChannelCreate    = "channel.create"
	VoiceCreate      = "voice.create"
	VoiceManageAny   = "voice.manage_any"
	VoiceBypassLocks = "voice.bypass_locks"
)

// IRCPrefix starts every IRC permission; the rest is the Ergo capability.
const IRCPrefix = "irc."

// Permission describes one entry of the catalog.
type Permission struct {
	ID          string `json:"id"`
	Group       string `json:"group"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// ircCapabilities are the oper capabilities Ergo v2.19.1 checks
// (irc/commands.go, HasRoleCapab(s) calls, default.yaml oper-classes).
// Ergo has no "kick" or "die" capability; opers kick through samode.
var ircCapabilities = []Permission{
	{Label: "Kill", ID: "kill", Description: "Disconnect users (KILL, NickServ LOGOUT of other users' sessions)"},
	{Label: "Ban", ID: "ban", Description: "Ban IPs, CIDRs and masks and suspend accounts (UBAN, DLINE, KLINE)"},
	{Label: "No fakelag", ID: "nofakelag", Description: "Exempt from fakelag message-rate limits"},
	{Label: "Relay messages", ID: "relaymsg", Description: "Use RELAYMSG in any channel"},
	{Label: "Vhosts", ID: "vhosts", Description: "Set and remove other users' vhosts (HostServ)"},
	{Label: "SAJOIN", ID: "sajoin", Description: "Join arbitrary channels, including private ones, and force-join users"},
	{Label: "SAMODE", ID: "samode", Description: "Change arbitrary channel and user modes (also needed to kick without op)"},
	{Label: "Snomasks", ID: "snomasks", Description: "Subscribe to arbitrary server notice masks"},
	{Label: "Roleplay", ID: "roleplay", Description: "Use the (deprecated) roleplay commands in any channel"},
	{Label: "Rehash", ID: "rehash", Description: "Reload the IRC server configuration at runtime"},
	{Label: "Account registrations", ID: "accreg", Description: "Modify or unregister arbitrary accounts (NickServ)"},
	{Label: "Channel registrations", ID: "chanreg", Description: "Modify or unregister arbitrary channel registrations (ChanServ)"},
	{Label: "History", ID: "history", Description: "Modify or delete history messages"},
	{Label: "DEFCON", ID: "defcon", Description: "Use DEFCON to restrict server capabilities"},
	{Label: "Mass message", ID: "massmessage", Description: "Message every user on the server"},
	{Label: "Metadata", ID: "metadata", Description: "Modify arbitrary metadata on channels and users"},
}

var catalog = func() []Permission {
	out := []Permission{
		{AdminPanel, GroupAdmin, "Open the admin panel", "Sign in to the admin panel and see roles and settings"},
		{UsersView, GroupAdmin, "View users", "List and search users, see their sessions and roles"},
		{UsersManage, GroupAdmin, "Manage users", "Create and edit users, disable and enable them, send password resets and verification emails"},
		{UsersModerate, GroupAdmin, "Moderate users", "Disable and enable users and revoke their sessions"},
		{InvitesManage, GroupAdmin, "Manage invites", "Create, list and revoke invite codes"},
		{SettingsManage, GroupAdmin, "Manage network settings", "Change registration, email verification and channel creation settings"},
		{SSOManage, GroupAdmin, "Manage SSO", "Add, edit and remove OIDC and SAML identity providers"},
		{ServicesView, GroupAdmin, "View services", "See the status of network services (admin panel)"},
		{ServicesManage, GroupAdmin, "Manage services", "Control network services (admin panel)"},
		{AuditView, GroupAdmin, "View audit log", "Read the audit log"},
		{RolesManage, GroupAdmin, "Manage roles", "Create, edit, delete and assign roles below your own"},
		{RolesOwner, GroupAdmin, "Manage the Owner role", "Edit the Owner role and grant or remove it (ownership transfer)"},
		{DirectoryManage, GroupAdmin, "Manage the directory", "Edit the public channel directory (admin panel)"},
		{ChannelCreate, GroupNetwork, "Create channels", "Register IRC text channels"},
		{VoiceCreate, GroupNetwork, "Create voice channels", "Create voice channels"},
		{VoiceManageAny, GroupNetwork, "Manage any voice channel", "Moderate, edit and delete any voice channel"},
		{VoiceBypassLocks, GroupNetwork, "Bypass voice locks", "Join locked or full voice channels"},
	}
	for _, c := range ircCapabilities {
		out = append(out, Permission{ID: IRCPrefix + c.ID, Group: GroupIRC, Label: "IRC: " + c.Label, Description: c.Description})
	}
	return out
}()

var index = func() map[string]int {
	m := make(map[string]int, len(catalog))
	for i, p := range catalog {
		m[p.ID] = i
	}
	return m
}()

// All returns the catalog in display order (a copy).
func All() []Permission { return slices.Clone(catalog) }

// IDs returns every permission id in catalog order.
func IDs() []string {
	out := make([]string, len(catalog))
	for i, p := range catalog {
		out[i] = p.ID
	}
	return out
}

// Valid reports whether id is in the catalog.
func Valid(id string) bool {
	_, ok := index[id]
	return ok
}

// Group returns the group of a known permission ("" if unknown).
func Group(id string) string {
	if i, ok := index[id]; ok {
		return catalog[i].Group
	}
	return ""
}

// IsIRC reports whether id is an IRC (Ergo capability) permission.
func IsIRC(id string) bool { return Group(id) == GroupIRC }

// IRCCapability returns the Ergo capability name of an irc.* permission.
func IRCCapability(id string) string { return strings.TrimPrefix(id, IRCPrefix) }

// Normalize validates ids and returns them de-duplicated in catalog order.
func Normalize(ids []string) ([]string, error) {
	seen := make(map[string]bool, len(ids))
	var unknown []string
	for _, id := range ids {
		if !Valid(id) {
			unknown = append(unknown, id)
			continue
		}
		seen[id] = true
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown permissions: %s", strings.Join(unknown, ", "))
	}
	return Sort(keys(seen)), nil
}

// Sort orders known ids by catalog position (unknown ids are dropped).
func Sort(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if Valid(id) {
			out = append(out, id)
		}
	}
	slices.SortFunc(out, func(a, b string) int { return index[a] - index[b] })
	return slices.Compact(out)
}

// Filter returns the ids that belong to group, in the given order.
func Filter(ids []string, group string) []string {
	out := []string{}
	for _, id := range ids {
		if Group(id) == group {
			out = append(out, id)
		}
	}
	return out
}

// Without returns every catalog id except the given ones.
func Without(except ...string) []string {
	out := []string{}
	for _, id := range IDs() {
		if !slices.Contains(except, id) {
			out = append(out, id)
		}
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
