package mailer

import (
	"context"
	"errors"
	"testing"

	"github.com/boson-chat/auth/config"
)

func TestNewWithoutHost(t *testing.T) {
	cfg := config.SMTPConfig{From: "Boson <hi@example.com>", Port: 587}

	dev, err := New(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dev.(LogMailer); !ok || !Configured(dev) {
		t.Fatalf("development: %T configured=%v, want the log mailer (counts as configured)", dev, Configured(dev))
	}

	prod, err := New(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := prod.(Disabled); !ok || Configured(prod) {
		t.Fatalf("production: %T configured=%v, want Disabled", prod, Configured(prod))
	}
	if err := prod.Send(context.Background(), Message{To: "a@example.com", Link: "https://x/#token=secret"}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Disabled.Send = %v, want ErrNotConfigured", err)
	}
	if FromAddress(prod) != cfg.From {
		t.Fatalf("from = %q", FromAddress(prod))
	}

	cfg.Host = "smtp.example.com"
	for _, dev := range []bool{true, false} {
		m, err := Factory(dev)(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := m.(*SMTPMailer); !ok || !Configured(m) {
			t.Fatalf("with host (dev=%v): %T", dev, m)
		}
	}
}

func TestConfiguredFollowsSwappable(t *testing.T) {
	sw := NewSwappable(Disabled{})
	if Configured(sw) {
		t.Fatal("disabled behind a Swappable counts as configured")
	}
	sw.Set(LogMailer{})
	if !Configured(sw) {
		t.Fatal("swapped to a working mailer: still not configured")
	}
	if Configured(nil) {
		t.Fatal("nil mailer counts as configured")
	}
}
