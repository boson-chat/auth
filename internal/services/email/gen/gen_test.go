package main

import (
	"context"
	"strings"
	"testing"

	mjml "github.com/Boostport/mjml-go"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/services/email"
)

// Boson's default MJML (GET /internal/email/default-mjml) compiles with
// strict validation, MJML keeps every {{placeholder}}, and auth accepts the
// result as a layout / a whole email.
func TestDefaultMJMLCompiles(t *testing.T) {
	ctx := context.Background()
	for _, part := range email.MJMLParts {
		src, err := email.DefaultMJML(part)
		if err != nil {
			t.Fatal(part, err)
		}
		out, err := mjml.ToHTML(ctx, src, mjml.WithFonts(mjml.Fonts{}),
			mjml.WithValidationLevel(mjml.Strict), mjml.WithKeepComments(true))
		if err != nil {
			t.Fatalf("%s: %v", part, err)
		}
		want := []string{"{{subject}}", "{{sender_name}}", "{{footer}}", "{{accent}}"}
		if part == "layout" {
			want = append(want, "{{content}}")
		} else {
			want = append(want, `href="{{link}}"`, "{{network}}")
		}
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: %s missing from the compiled HTML", part, w)
			}
		}
		if err := email.CheckCustomHTML(out, part == "layout"); err != nil {
			t.Errorf("%s: %v", part, err)
		}
	}
	if _, err := email.DefaultMJML(config.EmailInvite + "x"); err == nil {
		t.Fatal("unknown part")
	}
}
