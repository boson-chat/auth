package config

import "testing"

func TestActingTokenMustDifferFromInternalToken(t *testing.T) {
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	c.InternalConfig = InternalConfig{APIToken: "same", ActingToken: "same"}
	if c.Validate() == nil {
		t.Fatal("INTERNAL_ACTING_TOKEN equal to INTERNAL_API_TOKEN accepted")
	}
	c.InternalConfig.ActingToken = "other"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.InternalConfig = InternalConfig{}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestChannelSettingDefaults(t *testing.T) {
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !c.AccountConfig.ChannelAutoRegister || c.AccountConfig.ChannelExpiryDays != 0 {
		t.Fatalf("defaults: auto_register=%v expiry_days=%d", c.AccountConfig.ChannelAutoRegister, c.AccountConfig.ChannelExpiryDays)
	}
	for _, n := range []int{0, 1, 90, MaxChannelExpiryDays} {
		c.AccountConfig.ChannelExpiryDays = n
		if err := c.Validate(); err != nil {
			t.Fatalf("CHANNEL_EXPIRY_DAYS=%d: %v", n, err)
		}
	}
	for _, n := range []int{-1, MaxChannelExpiryDays + 1} {
		c.AccountConfig.ChannelExpiryDays = n
		if c.Validate() == nil {
			t.Fatalf("CHANNEL_EXPIRY_DAYS=%d accepted", n)
		}
	}
}

func TestChannelSettingsFromEnv(t *testing.T) {
	t.Setenv("CHANNEL_AUTO_REGISTER", "false")
	t.Setenv("CHANNEL_EXPIRY_DAYS", "30")
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.AccountConfig.ChannelAutoRegister || c.AccountConfig.ChannelExpiryDays != 30 {
		t.Fatalf("env: auto_register=%v expiry_days=%d", c.AccountConfig.ChannelAutoRegister, c.AccountConfig.ChannelExpiryDays)
	}
	t.Setenv("CHANNEL_EXPIRY_DAYS", "4000")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("CHANNEL_EXPIRY_DAYS=4000 accepted at startup")
	}
}
