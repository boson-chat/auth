package config

import (
	"fmt"
	"strings"
)

// Guest-first entry (auth.guest_first / GUEST_FIRST): Boson web clients
// open straight into chat as a guest, with a ready nick and a "Join chat"
// button, and keep sign-in and sign-up one click away. They land on
// auth.guest_first_channel (GUEST_FIRST_CHANNEL), by default the first
// auto-join network channel guests may join.

// ValidateGuestFirst checks the guest-first settings together: guest_first
// needs guest_access, and guest_first_channel ("" = default) must be a
// channel name guests may join (not a network channel restricted to roles).
func ValidateGuestFirst(guestAccess, guestFirst bool, channel string, channels []NetworkChannel) error {
	if guestFirst && !guestAccess {
		return fmt.Errorf("GUEST_FIRST (auth.guest_first) requires GUEST_ACCESS (auth.guest_access)")
	}
	return CheckGuestFirstChannel(channel, channels)
}

// CheckGuestFirstChannel returns an error when channel ("" = default) can't
// be guest-first clients' landing channel.
func CheckGuestFirstChannel(channel string, channels []NetworkChannel) error {
	if channel == "" {
		return nil
	}
	if msg := CheckChannelName(channel); msg != "" {
		return fmt.Errorf("guest_first_channel: %s", msg)
	}
	for _, c := range channels {
		if strings.EqualFold(c.Name, channel) && c.Restricted() {
			return fmt.Errorf("guest_first_channel: %s is restricted to roles, so guests can't join it", c.Name)
		}
	}
	return nil
}

// GuestFirstLanding is the channel guest-first clients land on: channel
// when set, else the first auto-join network channel open to guests, else
// "" (the client's own default).
func GuestFirstLanding(channel string, channels []NetworkChannel) string {
	if channel != "" {
		return channel
	}
	for _, c := range channels {
		if c.Autojoin && !c.Restricted() {
			return c.Name
		}
	}
	return ""
}
