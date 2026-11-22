package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/boson-chat/auth/internal/configfile"
	"gopkg.in/yaml.v3"
)

func TestNetworkChannelsFromFile(t *testing.T) {
	f, err := loadFile(t, `version: 1
irc:
  plaintext: true          # the boson-ergo helper's key: not unknown
  channels:
    - name: " #Lobby "
      topic: "  Welcome to Boson "
      autojoin: true
    - { name: "#help", colour: red }
  channel_founder: thelion
  autojoin_guests: false
`)
	if err != nil {
		t.Fatal(err)
	}
	if !f.IRCChannelsSet || fmt.Sprint(f.IRCChannels) != "[{#Lobby Welcome to Boson true []} {#help  false []}]" {
		t.Fatalf("%+v", f.IRCChannels)
	}
	if *f.IRCChannelFounder != "thelion" || *f.IRCAutojoinGuests {
		t.Fatalf("%+v", f)
	}
	if strings.Join(f.Unknown, ",") != "irc.channels[1].colour" {
		t.Fatalf("unknown %v", f.Unknown)
	}
	if f.IRCChannels[0].Folded() != "#lobby" {
		t.Fatal(f.IRCChannels[0].Folded())
	}
	m := f.Flatten()
	if fmt.Sprint(m[KeyIRCChannels]) != "[map[autojoin:true name:#Lobby topic:Welcome to Boson] map[autojoin:false name:#help topic:]]" ||
		m[KeyIRCChannelFounder] != "thelion" || m[KeyIRCAutojoinGuests] != false {
		t.Fatalf("flatten %v", m)
	}

	env := Config{IRCConfig: IRCConfig{AutojoinGuests: true, ChannelFounder: "env"}}
	got := env.WithFile(f).IRCConfig
	if len(got.Channels) != 2 || got.ChannelFounder != "thelion" || got.AutojoinGuests {
		t.Fatalf("with file %+v", got)
	}
	// absent keys keep the env values
	f, _ = loadFile(t, "version: 1\nirc: { plaintext: true }\n")
	if got := env.WithFile(f).IRCConfig; got.Channels != nil || got.ChannelFounder != "env" || !got.AutojoinGuests || len(f.Flatten()) != 0 {
		t.Fatalf("absent %+v", got)
	}
	// an empty list is a set, empty list
	f, _ = loadFile(t, "version: 1\nirc: { channels: [] }\n")
	if !f.IRCChannelsSet || len(f.IRCChannels) != 0 {
		t.Fatalf("empty %+v", f)
	}
}

func TestNetworkChannelsValidation(t *testing.T) {
	many := "version: 1\nirc:\n  channels:\n"
	for i := 0; i <= MaxNetworkChannels; i++ {
		many += fmt.Sprintf("    - name: \"#c%d\"\n", i)
	}
	for _, tc := range []struct{ src, want string }{
		{"irc: { channels: \"#lobby\" }", "irc.channels: must be a list"},
		{"irc: { channels: [\"#lobby\"] }", "irc.channels[0]: must be a mapping"},
		{"irc: { channels: [{ topic: hi }] }", "irc.channels[0].name: is required"},
		{"irc: { channels: [{ name: lobby }] }", "must start with #"},
		{"irc: { channels: [{ name: \"#a b\" }] }", "printable ASCII"},
		{"irc: { channels: [{ name: \"#a,b\" }] }", "printable ASCII"},
		{"irc: { channels: [{ name: \"#" + strings.Repeat("x", 64) + "\" }] }", "longer than 64"},
		{"irc: { channels: [{ name: \"#Lobby\" }, { name: \"#lobby\" }] }", "irc.channels[1].name: channel #lobby is listed twice"},
		{"irc: { channels: [{ name: \"#a\", topic: \"" + strings.Repeat("é", 301) + "\" }] }", "at most 300"},
		{"irc: { channels: [{ name: \"#a\", topic: \"a\\nb\" }] }", "one line"},
		{"irc: { channels: [{ name: \"#a\", autojoin: yes please }] }", "irc.channels[0].autojoin: must be true or false"},
		{"irc: { channel_founder: \"no spaces\" }", "irc.channel_founder: must be an account name"},
		{"irc: { channel_founder: " + strings.Repeat("a", 31) + " }", "must be an account name"},
		{"irc: { autojoin_guests: maybe }", "irc.autojoin_guests: must be true or false"},
		{"irc: { channels: [{ name: \"#a\", roles: { admin: true } }] }", "irc.channels[0].roles: must be a list of strings"},
		{"irc: { channels: [{ name: \"#a\", roles: [[Admin]] }] }", "every item must be a string"},
		{"irc: { channels: [{ name: \"#a\", roles: [\"Admin!\"] }] }", "irc.channels[0].roles: role \"Admin!\" may only contain letters"},
		{"irc: { channels: [{ name: \"#a\", roles: [\"" + strings.Repeat("x", 33) + "\"] }] }", "must be 1-32 characters"},
		{"irc: { channels: [{ name: \"#a\", roles: [\" \"] }] }", "must be 1-32 characters"},
		{strings.TrimPrefix(many, "version: 1\n"), "at most 100 network channels"},
	} {
		_, err := loadFile(t, "version: 1\n"+tc.src+"\n")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%.60s: got %v, want %q", tc.src, err, tc.want)
		}
		if e, ok := configfile.AsError(err); err != nil && (!ok || e.Line == 0) {
			t.Errorf("%.60s: no position: %v", tc.src, err)
		}
	}
	// 300 characters is fine; an empty founder means the default
	f, err := loadFile(t, "version: 1\nirc: { channel_founder: \"\", channels: [{ name: \"#a\", topic: \""+strings.Repeat("é", 300)+"\" }] }\n")
	if err != nil || *f.IRCChannelFounder != "" {
		t.Fatal(err)
	}
}

func TestExportIRC(t *testing.T) {
	env := envConfig()
	env.IRCConfig = IRCConfig{AutojoinGuests: true}
	out, err := ExportFile(env, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "irc:") {
		t.Fatalf("defaults aren't exported:\n%s", out)
	}
	env.IRCConfig = IRCConfig{ChannelFounder: "thelion", Channels: []NetworkChannel{{Name: "#Lobby", Topic: "Hi", Autojoin: true}, {Name: "#help", Roles: []string{"Admin", "Chat Helper"}}}}
	out, err = ExportFile(env, false)
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := yaml.Unmarshal(out, &probe); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	f, err := loadFile(t, "version: 1\n"+string(out))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := (Config{}).WithFile(f).IRCConfig
	if fmt.Sprint(got) != "{[{#Lobby Hi true []} {#help  false [Admin Chat Helper]}] thelion false}" {
		t.Fatalf("round trip %+v\n%s", got, out)
	}
}

func TestNetworkChannelRoles(t *testing.T) {
	f, err := loadFile(t, `version: 1
irc:
  channels:
    - name: "#opers"
      roles: [ Admin, " Owner ", admin ]   # trimmed, de-duplicated case-insensitively
    - name: "#staff"
      roles: Chat Helper                   # one role as a string
    - name: "#lobby"
      roles:                               # null: everyone
    - name: "#news"
      roles: []
`)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(f.IRCChannels)
	if got != "[{#opers  false [Admin Owner]} {#staff  false [Chat Helper]} {#lobby  false []} {#news  false []}]" {
		t.Fatal(got)
	}
	if !f.IRCChannels[0].Restricted() || f.IRCChannels[2].Restricted() || f.IRCChannels[3].Restricted() || len(f.Unknown) != 0 {
		t.Fatalf("%+v %v", f.IRCChannels, f.Unknown)
	}
	if m := fmt.Sprint(f.Flatten()[KeyIRCChannels]); m != "[map[autojoin:false name:#opers roles:[Admin Owner] topic:] map[autojoin:false name:#staff roles:[Chat Helper] topic:] map[autojoin:false name:#lobby topic:] map[autojoin:false name:#news topic:]]" {
		t.Fatal(m)
	}
	many := make([]string, MaxChannelRoles+1)
	for i := range many {
		many[i] = fmt.Sprintf("r%d", i)
	}
	if _, err := loadFile(t, "version: 1\nirc: { channels: [{ name: \"#a\", roles: ["+strings.Join(many, ", ")+"] }] }\n"); err == nil || !strings.Contains(err.Error(), "at most 32 roles") {
		t.Fatal(err)
	}
}
