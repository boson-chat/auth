package commands

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	authhttp "github.com/boson-chat/auth/http"
	"github.com/spf13/cobra"
)

var inviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Manage registration invites (REGISTRATION=invite)",
}

var inviteCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Mint an invite code (printed once)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		uses, _ := cmd.Flags().GetInt("uses")
		ttl, _ := cmd.Flags().GetDuration("ttl")
		note, _ := cmd.Flags().GetString("note")
		return withApp(cmd.Context(), func(ctx context.Context, app *authhttp.App) error {
			code, inv, err := app.Admin.CreateInvite(ctx, "", uses, ttl, note)
			if err != nil {
				return err
			}
			exp := "never"
			if inv.ExpiresAt != nil {
				exp = inv.ExpiresAt.Format(time.RFC3339)
			}
			fmt.Fprintf(os.Stderr, "invite %s: %d use(s), expires %s\n", inv.ID, inv.MaxUses, exp)
			fmt.Println(code)
			return nil
		})
	},
}

var inviteListCmd = &cobra.Command{
	Use:   "list",
	Short: "List invites",
	RunE: func(cmd *cobra.Command, _ []string) error {
		return withApp(cmd.Context(), func(ctx context.Context, app *authhttp.App) error {
			list, err := app.Admin.ListInvites(ctx, 200)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tUSES\tEXPIRES\tREVOKED\tNOTE")
			for _, i := range list {
				exp := "never"
				if i.ExpiresAt != nil {
					exp = i.ExpiresAt.Format(time.RFC3339)
				}
				fmt.Fprintf(tw, "%s\t%d/%d\t%s\t%v\t%s\n", i.ID, i.Uses, i.MaxUses, exp, i.RevokedAt != nil, i.Note)
			}
			return tw.Flush()
		})
	},
}

var inviteRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke an invite",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withApp(cmd.Context(), func(ctx context.Context, app *authhttp.App) error {
			return app.Admin.RevokeInvite(ctx, "", args[0])
		})
	},
}

func init() {
	inviteCreateCmd.Flags().Int("uses", 1, "how many registrations the code admits")
	inviteCreateCmd.Flags().Duration("ttl", 7*24*time.Hour, "lifetime (0 = never expires)")
	inviteCreateCmd.Flags().String("note", "", "free-text note")
	inviteCmd.AddCommand(inviteCreateCmd, inviteListCmd, inviteRevokeCmd)
	rootCmd.AddCommand(inviteCmd)
}
