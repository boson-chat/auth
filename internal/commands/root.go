// Package commands holds the cobra CLI: serve, migrate and admin commands.
package commands

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "auth",
	Short:         "boson authentication service",
	SilenceUsage:  true,
	SilenceErrors: false,
}

// Execute runs the root command and exits non-zero on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
