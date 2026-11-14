// Command gen compiles templates/layout.mjml into the HTML the email
// package embeds (templates/compiled/*.html). Run it with go generate from
// internal/services/email; it is the only code that links MJML (mjml-go,
// MJML as wasm on wazero), so the server binary doesn't carry its runtime.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	mjml "github.com/Boostport/mjml-go"

	"github.com/boson-chat/auth/internal/services/email"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "email/gen:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	for i, footer := range []bool{false, true} {
		src, err := email.LayoutMJML(footer)
		if err != nil {
			return err
		}
		// No web fonts (the system stack names Roboto, which MJML would
		// otherwise import from Google Fonts); strict validation so a
		// broken layout fails here; keep comments (the bx: markers and
		// Outlook's conditional comments).
		out, err := mjml.ToHTML(ctx, src, mjml.WithFonts(mjml.Fonts{}),
			mjml.WithValidationLevel(mjml.Strict), mjml.WithKeepComments(true))
		if err != nil {
			return fmt.Errorf("mjml: %w", err)
		}
		// The email package checks the markers and slots when it loads.
		path := email.CompiledLayoutFiles[i]
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
			return err
		}
	}
	return nil
}
