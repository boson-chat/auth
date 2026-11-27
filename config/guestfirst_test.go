package config

import (
	"strings"
	"testing"
)

func TestValidateGuestFirst(t *testing.T) {
	chans := []NetworkChannel{{Name: "#Opers", Roles: []string{"Admin"}}, {Name: "#lobby", Autojoin: true}}
	cases := []struct {
		access, first bool
		channel       string
		err           string
	}{
		{true, true, "", ""},
		{false, false, "", ""},
		{true, true, "#lobby", ""},
		{true, true, "#elsewhere", ""},
		{false, true, "", "requires GUEST_ACCESS"},
		{true, true, "lobby", "must start with #"},
		{true, true, "#opers", "restricted to roles"},
		{true, false, "#a b", "printable ASCII"},
	}
	for _, c := range cases {
		err := ValidateGuestFirst(c.access, c.first, c.channel, chans)
		if (err == nil) != (c.err == "") || err != nil && !strings.Contains(err.Error(), c.err) {
			t.Errorf("%+v: got %v", c, err)
		}
	}
}

func TestGuestFirstLanding(t *testing.T) {
	chans := []NetworkChannel{
		{Name: "#news"},
		{Name: "#staff", Autojoin: true, Roles: []string{"Admin"}},
		{Name: "#IRCForever", Autojoin: true},
		{Name: "#help", Autojoin: true},
	}
	if got := GuestFirstLanding("", chans); got != "#IRCForever" {
		t.Fatal(got)
	}
	if got := GuestFirstLanding("#help", chans); got != "#help" {
		t.Fatal(got)
	}
	if got := GuestFirstLanding("", chans[:2]); got != "" {
		t.Fatal(got)
	}
	if got := GuestFirstLanding("", nil); got != "" {
		t.Fatal(got)
	}
}

func TestConfigValidateGuestFirst(t *testing.T) {
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.AccountConfig.GuestFirst || c.AccountConfig.GuestFirstChannel != "" {
		t.Fatalf("defaults: %+v", c.AccountConfig)
	}
	c.AccountConfig.GuestFirst, c.AccountConfig.GuestAccess = true, false
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "GUEST_FIRST") {
		t.Fatal(err)
	}
	c.AccountConfig.GuestAccess = true
	c.AccountConfig.GuestFirstChannel = "#ok"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GUEST_FIRST", "true")
	t.Setenv("GUEST_FIRST_CHANNEL", "#IRCForever")
	if c, err = LoadConfig(); err != nil || !c.AccountConfig.GuestFirst || c.AccountConfig.GuestFirstChannel != "#IRCForever" {
		t.Fatalf("%+v %v", c.AccountConfig, err)
	}
}
