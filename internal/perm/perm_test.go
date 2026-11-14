package perm

import (
	"slices"
	"testing"
)

func TestCatalog(t *testing.T) {
	ids := IDs()
	if len(ids) != 33 {
		t.Fatalf("catalog has %d permissions", len(ids))
	}
	seen := map[string]bool{}
	for _, p := range All() {
		if seen[p.ID] || p.Label == "" || p.Description == "" {
			t.Fatalf("bad entry %+v", p)
		}
		seen[p.ID] = true
		if (p.Group == GroupIRC) != (len(p.ID) > 4 && p.ID[:4] == IRCPrefix) {
			t.Fatalf("irc group mismatch: %+v", p)
		}
	}
	// Ergo v2.19.1 oper capabilities, 1:1.
	var caps []string
	for _, id := range Filter(ids, GroupIRC) {
		caps = append(caps, IRCCapability(id))
	}
	want := []string{"kill", "ban", "nofakelag", "relaymsg", "vhosts", "sajoin", "samode", "snomasks", "roleplay",
		"rehash", "accreg", "chanreg", "history", "defcon", "massmessage", "metadata"}
	if !slices.Equal(caps, want) {
		t.Fatalf("irc caps = %v", caps)
	}
	for _, missing := range []string{"irc.kick", "irc.die", "irc.local_kill", "admin", ""} {
		if Valid(missing) {
			t.Fatalf("%q must not be valid", missing)
		}
	}
}

func TestNormalize(t *testing.T) {
	got, err := Normalize([]string{"irc.ban", "admin.panel", "irc.ban", "channel.create"})
	if err != nil || !slices.Equal(got, []string{"admin.panel", "channel.create", "irc.ban"}) {
		t.Fatalf("Normalize = %v, %v", got, err)
	}
	if _, err := Normalize([]string{"admin.panel", "irc.kick", "nope"}); err == nil || err.Error() != "unknown permissions: irc.kick, nope" {
		t.Fatalf("err = %v", err)
	}
	if got, _ := Normalize(nil); got == nil || len(got) != 0 {
		t.Fatalf("Normalize(nil) = %#v, want empty", got)
	}
	if got := Sort([]string{"voice.create", "gone", "admin.panel"}); !slices.Equal(got, []string{"admin.panel", "voice.create"}) {
		t.Fatalf("Sort = %v", got)
	}
	if w := Without(RolesOwner); len(w) != 32 || slices.Contains(w, RolesOwner) {
		t.Fatalf("Without = %v", w)
	}
	if !IsIRC("irc.samode") || IsIRC("voice.create") || Group("x") != "" {
		t.Fatal("groups")
	}
}
