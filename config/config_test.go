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
