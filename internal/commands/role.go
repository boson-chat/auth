package commands

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	authhttp "github.com/boson-chat/auth/http"
	"github.com/boson-chat/auth/internal/services/roles"
	"github.com/spf13/cobra"
)

var roleCmd = &cobra.Command{
	Use:   "role",
	Short: "Network roles",
}

var roleListCmd = &cobra.Command{
	Use:   "list",
	Short: "List roles, most senior first",
	RunE: func(cmd *cobra.Command, _ []string) error {
		return withApp(cmd.Context(), func(ctx context.Context, app *authhttp.App) error {
			vs, err := app.Roles.List(ctx)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tPOSITION\tMEMBERS\tOPER\tPERMISSIONS")
			for _, v := range vs {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%v\t%d\n", v.ID, v.Name, v.Position, v.MemberCount, roles.EffectiveOper(v.Role), len(roles.EffectivePermissions(v.Role)))
			}
			return tw.Flush()
		})
	},
}

// resolveRoles maps role names (case-insensitive) or ids to ids.
func resolveRoles(ctx context.Context, app *authhttp.App, args []string) ([]string, error) {
	vs, err := app.Roles.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(args))
	for _, a := range args {
		found := ""
		for _, v := range vs {
			if v.ID == a || strings.EqualFold(v.Name, a) {
				found = v.ID
				break
			}
		}
		if found == "" {
			return nil, fmt.Errorf("no role %q", a)
		}
		out = append(out, found)
	}
	return out, nil
}

var userSetRolesCmd = &cobra.Command{
	Use:   "set-roles <id|username> [role...]",
	Short: "Replace a user's roles (names or ids; none = Member only)",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withApp(cmd.Context(), func(ctx context.Context, app *authhttp.App) error {
			u, err := app.Admin.FindUser(ctx, args[0])
			if err != nil {
				return err
			}
			ids, err := resolveRoles(ctx, app, args[1:])
			if err != nil {
				return err
			}
			rs, err := app.Roles.SetUserRoles(ctx, "", u.ID, ids)
			if err != nil {
				return err
			}
			names := []string{}
			for _, r := range rs {
				names = append(names, r.Name)
			}
			fmt.Printf("%s roles=%s\n", u.Username, strings.Join(names, ","))
			return nil
		})
	},
}

func init() {
	roleCmd.AddCommand(roleListCmd)
	userCmd.AddCommand(userSetRolesCmd)
	rootCmd.AddCommand(roleCmd)
}
