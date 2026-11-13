package commands

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	authhttp "github.com/boson-chat/auth/http"
	"github.com/spf13/cobra"
)

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage JWT signing keys",
}

var keysRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Create a new signing key (published now, signs after KEY_PUBLISH_LEAD; --now to sign immediately)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		now, _ := cmd.Flags().GetBool("now")
		return withApp(cmd.Context(), func(ctx context.Context, app *authhttp.App) error {
			kid, err := app.Keys.Rotate(ctx, now)
			if err != nil {
				return err
			}
			fmt.Printf("new signing key %s\n", kid)
			return nil
		})
	},
}

var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List signing keys and their state",
	RunE: func(cmd *cobra.Command, _ []string) error {
		return withApp(cmd.Context(), func(ctx context.Context, app *authhttp.App) error {
			list, err := app.Keys.List(ctx)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "KID\tSTATE\tCREATED\tACTIVATED\tRETIRED")
			for _, k := range list {
				ret := "-"
				if k.RetiredAt != nil {
					ret = k.RetiredAt.Format(time.RFC3339)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", k.KID, k.State, k.CreatedAt.Format(time.RFC3339), k.ActivatedAt.Format(time.RFC3339), ret)
			}
			return tw.Flush()
		})
	},
}

var keysGenKEKCmd = &cobra.Command{
	Use:   "gen-kek",
	Short: "Print a new random AUTH_KEY_ENCRYPTION_KEY (32 bytes, base64)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(b))
		return nil
	},
}

func init() {
	keysRotateCmd.Flags().Bool("now", false, "sign with the new key immediately (e.g. after a key compromise)")
	keysCmd.AddCommand(keysRotateCmd, keysListCmd, keysGenKEKCmd)
	rootCmd.AddCommand(keysCmd)
}
