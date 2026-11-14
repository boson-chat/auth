package email

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/apperr"
	"github.com/boson-chat/auth/internal/mailer"
)

func ptr[T any](v T) *T { return &v }

func TestPreviewEmailOverrides(t *testing.T) {
	s := newSvc(mailer.LogMailer{From: "boson <no-reply@example.com>"}, "https://auth.example.com/logo.png", nil)
	ctx := context.Background()

	// Nothing saved, no overrides: the built-in email, From = SMTP_FROM.
	r, err := s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile("testdata/legacy/verify.html")
	if r.From != "boson <no-reply@example.com>" || !strings.HasPrefix(r.HTML, "<!doctype html>\n<html><body") || len(want) == 0 {
		t.Fatalf("%+v", r)
	}
	// An empty email object changes nothing.
	r2, _ := s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification, Email: &EmailOverrides{}})
	if r2.HTML != r.HTML {
		t.Fatal("empty overrides = none")
	}

	// Overrides with nothing saved: the branded layout with those values.
	r, err = s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification, Email: &EmailOverrides{
		SenderName: ptr("  Example Chat "), Accent: ptr("#7C3AED"), Footer: ptr(" Example Chat · https://example.com "), Logo: ptr(true),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if r.From != `"Example Chat" <no-reply@example.com>` || !strings.Contains(r.HTML, `bgcolor="#7c3aed"`) ||
		!strings.Contains(r.HTML, `<img src="https://auth.example.com/logo.png" alt="Example Chat"`) ||
		!strings.HasSuffix(r.Text, "\n-- \nExample Chat · https://example.com\n") {
		t.Fatalf("%+v", r)
	}

	// Saved settings: missing fields fall back to them.
	sub := "Saved {{network}}"
	s.SetConfig(&config.EmailConfig{SenderName: "Saved", Accent: "#112233", Footer: "Saved footer", Logo: true,
		Templates: map[string]config.EmailTemplate{config.EmailVerification: {Subject: &sub}}})
	r, _ = s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification, Email: &EmailOverrides{Accent: ptr("#aabbcc")}})
	if !strings.Contains(r.HTML, `bgcolor="#aabbcc"`) || !strings.Contains(r.HTML, `alt="Saved"`) || r.From != `"Saved" <no-reply@example.com>` ||
		!strings.Contains(r.Text, "Saved footer") || r.Subject != "Saved "+site {
		t.Fatalf("%+v", r)
	}
	// logo:false and "" fields (= the defaults) override the saved values.
	r, _ = s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification, Subject: ptr("Typed"),
		Email: &EmailOverrides{Logo: ptr(false), SenderName: ptr(""), Footer: ptr(""), Accent: ptr("")}})
	if strings.Contains(r.HTML, "<img") || !strings.Contains(r.HTML, ">Example &lt;Net&gt; &amp; Co</span>") ||
		!strings.Contains(r.HTML, `bgcolor="`+DefaultAccent+`"`) || strings.Contains(r.Text, "-- \n") ||
		r.Subject != "Typed" || r.From != "boson <no-reply@example.com>" {
		t.Fatalf("%+v", r)
	}
	// The saved config itself is untouched.
	if c := s.cfg.Load(); c.Accent != "#112233" || !c.Logo || c.SenderName != "Saved" {
		t.Fatalf("%+v", c)
	}
}

func TestPreviewValidation(t *testing.T) {
	s := newSvc(&capture{}, "", nil)
	ctx := context.Background()
	long := strings.Repeat("x", config.MaxSenderNameLen+1)
	for _, c := range []struct {
		in    PreviewInput
		field string
	}{
		{PreviewInput{Subject: ptr("two\nlines")}, "subject"},
		{PreviewInput{Body: ptr("  ")}, "body"},
		{PreviewInput{Body: ptr("bell\a")}, "body"},
		{PreviewInput{Email: &EmailOverrides{SenderName: ptr("a\nb")}}, "email.sender_name"},
		{PreviewInput{Email: &EmailOverrides{SenderName: &long}}, "email.sender_name"},
		{PreviewInput{Email: &EmailOverrides{Accent: ptr("red")}}, "email.accent"},
		{PreviewInput{Email: &EmailOverrides{Accent: ptr("#12345")}}, "email.accent"},
		{PreviewInput{Email: &EmailOverrides{Footer: ptr(strings.Repeat("f", config.MaxFooterLen+1))}}, "email.footer"},
		{PreviewInput{Email: &EmailOverrides{Footer: ptr("tab\tno")}}, "email.footer"},
	} {
		c.in.Template = config.EmailVerification
		_, err := s.Preview(ctx, "admin", c.in)
		e, ok := apperr.As(err)
		if !ok || e.Status != 400 || e.Code != "invalid_request" || e.Field != c.field || !strings.HasPrefix(e.Message, c.field+" ") {
			t.Errorf("%s: %v", c.field, err)
		}
	}
	if s.previews.len() != 0 {
		t.Fatal("invalid input is not cached")
	}
}

func TestPreviewCache(t *testing.T) {
	m := &swapFrom{from: "a <a@example.com>"}
	s := newSvc(m, "", nil)
	ctx := context.Background()
	in := PreviewInput{Template: config.EmailInvite, Body: ptr("Hello {{inviter}}")}
	a, _ := s.Preview(ctx, "admin", in)
	b, _ := s.Preview(ctx, "admin", in)
	if !reflect.DeepEqual(a, b) || s.previews.len() != 1 {
		t.Fatal("same input → one cache entry")
	}
	// Anything the email depends on is part of the key.
	for _, change := range []func(){
		func() { in.Body = ptr("Hello again") },
		func() { s.SetSiteName("Other") },
		func() { s.SetConfig(&config.EmailConfig{Accent: "#000000"}) },
		func() { m.from = "b <b@example.com>" },
		func() { s.opts.Logo = func() Logo { return Logo{URL: "https://x/l.png"} } },
	} {
		before := s.previews.len()
		change()
		r, _ := s.Preview(ctx, "admin", in)
		if s.previews.len() != before+1 {
			t.Fatalf("change not in the key: %+v", r)
		}
	}
	if r, _ := s.Preview(ctx, "admin2", in); !strings.HasPrefix(r.Subject, "admin2 invited") {
		t.Fatal("username is part of the key")
	}
	// Bounded.
	c := newPreviewCache(3)
	for i := range 10 {
		c.put([32]byte{byte(i)}, Rendered{Subject: fmt.Sprint(i)})
	}
	if c.len() != 3 {
		t.Fatal(c.len())
	}
	if _, ok := c.get([32]byte{9}); !ok {
		t.Fatal("newest kept")
	}
	if _, ok := c.get([32]byte{0}); ok {
		t.Fatal("oldest evicted")
	}
}

type swapFrom struct {
	capture
	from string
}

func (s *swapFrom) FromAddress() string { return s.from }

func TestFromHeader(t *testing.T) {
	for _, c := range [][3]string{
		{"boson <no-reply@x.example>", "", "boson <no-reply@x.example>"},
		{"boson <no-reply@x.example>", `Ex "Chat"`, `"Ex \"Chat\"" <no-reply@x.example>`},
		{"no-reply@x.example", "Ex", `"Ex" <no-reply@x.example>`},
		{"", "Ex", ""},
	} {
		if got := mailer.FromHeader(c[0], c[1]); got != c[2] {
			t.Errorf("FromHeader(%q, %q) = %q", c[0], c[1], got)
		}
	}
}

// The preview's budget: well under 100 ms warm. Uncached renders fill the
// precompiled skeleton (no MJML at request time); cached ones are a hash
// and a map lookup.
func TestPreviewLatencyBudget(t *testing.T) {
	s := goldenSvc()
	s.SetConfig(brandedCases()[config.EmailVerification])
	ctx := context.Background()
	start := time.Now()
	const n = 200
	for i := range n {
		if _, err := s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification, Body: ptr(fmt.Sprintf("Hi {{username}} %d\n\n{{link}}", i))}); err != nil {
			t.Fatal(err)
		}
	}
	if per := time.Since(start) / n; per > 10*time.Millisecond {
		t.Fatalf("uncached preview takes %v", per)
	}
}

func BenchmarkPreview(b *testing.B) {
	s := goldenSvc()
	s.SetConfig(brandedCases()[config.EmailVerification])
	ctx := context.Background()
	b.Run("uncached", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			// A new body each time: the cache never hits.
			in := PreviewInput{Template: config.EmailVerification, Body: ptr(fmt.Sprintf("Hi {{username}} %d\n\n{{link}}\n\nBye.", i))}
			if _, err := s.Preview(ctx, "admin", in); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("cached", func(b *testing.B) {
		b.ReportAllocs()
		in := PreviewInput{Template: config.EmailVerification, Email: &EmailOverrides{Accent: ptr("#aabbcc")}}
		for b.Loop() {
			if _, err := s.Preview(ctx, "admin", in); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("legacy", func(b *testing.B) {
		b.ReportAllocs()
		s := newSvc(&capture{}, "", nil)
		for i := 0; b.Loop(); i++ {
			s.previews = newPreviewCache(previewCacheSize) // measure the render
			if _, err := s.Preview(ctx, "admin", PreviewInput{Template: config.EmailVerification}); err != nil {
				b.Fatal(err)
			}
		}
	})
}
