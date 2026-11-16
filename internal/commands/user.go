package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	authhttp "github.com/boson-chat/auth/http"
	"github.com/boson-chat/auth/internal/opaque"
	"github.com/boson-chat/auth/internal/services/account"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage user accounts",
}

func readPassword(fromStdin bool) (string, bool, error) {
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", false, fmt.Errorf("reading password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), false, nil
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password (empty = generate one): ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", false, err
		}
		if len(b) > 0 {
			return string(b), false, nil
		}
	}
	// Random 32-char password, shown once.
	return opaque.New("")[:32], true, nil
}

var userCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a user (email marked verified). Prompts for the password, or reads it with --password-stdin",
	RunE: func(cmd *cobra.Command, _ []string) error {
		username, _ := cmd.Flags().GetString("username")
		emailAddr, _ := cmd.Flags().GetString("email")
		role, _ := cmd.Flags().GetString("role")
		stdin, _ := cmd.Flags().GetBool("password-stdin")
		noPassword, _ := cmd.Flags().GetBool("no-password")
		pw, generated := "", false
		if !noPassword {
			var err error
			if pw, generated, err = readPassword(stdin); err != nil {
				return err
			}
		}
		return withApp(cmd.Context(), func(ctx context.Context, app *authhttp.App) error {
			u, err := app.Account.CreateUser(ctx, "", account.CreateUserInput{
				Username: username, Email: emailAddr, Password: pw, Role: role, EmailVerified: true,
			})
			if err != nil {
				return err
			}
			fmt.Printf("created %s (%s) role=%s\n", u.Username, u.ID, u.Role)
			if generated {
				fmt.Fprintf(os.Stderr, "generated password (shown once): %s\n", pw)
			}
			return nil
		})
	},
}

var userListCmd = &cobra.Command{
	Use:   "list [query]",
	Short: "List users",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		q := ""
		if len(args) == 1 {
			q = args[0]
		}
		limit, _ := cmd.Flags().GetInt("limit")
		return withApp(cmd.Context(), func(ctx context.Context, app *authhttp.App) error {
			users, total, err := app.Admin.ListUsers(ctx, q, "", limit, 0)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tUSERNAME\tEMAIL\tVERIFIED\tROLE\tDISABLED")
			for _, u := range users {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\t%v\n", u.ID, u.Username, u.EmailOrEmpty(), u.EmailVerified(), u.Role, u.Disabled())
			}
			_ = tw.Flush()
			fmt.Printf("%d of %d\n", len(users), total)
			return nil
		})
	},
}

func userAction(use, short string, fn func(ctx context.Context, app *authhttp.App, id string) (any, error)) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withApp(cmd.Context(), func(ctx context.Context, app *authhttp.App) error {
				u, err := app.Admin.FindUser(ctx, args[0])
				if err != nil {
					return err
				}
				out, err := fn(ctx, app, u.ID)
				if err != nil {
					return err
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			})
		},
	}
}

func init() {
	userCreateCmd.Flags().String("username", "", "username / IRC nick (required)")
	userCreateCmd.Flags().String("email", "", "email address")
	userCreateCmd.Flags().String("role", "user", "user, admin (the Admin role) or owner (the Owner role)")
	userCreateCmd.Flags().Bool("password-stdin", false, "read the password from the first line of stdin")
	userCreateCmd.Flags().Bool("no-password", false, "create without a password (SSO-only)")
	_ = userCreateCmd.MarkFlagRequired("username")
	userListCmd.Flags().Int("limit", 50, "max rows")

	setRole := userAction("set-role <id|username> <role>", "Set a user's 1.x role: user (drop admin-panel roles) | admin (add Admin) | owner (add Owner)", nil)
	setRole.Args = cobra.ExactArgs(2)
	setRole.RunE = func(cmd *cobra.Command, args []string) error {
		return withApp(cmd.Context(), func(ctx context.Context, app *authhttp.App) error {
			u, err := app.Admin.FindUser(ctx, args[0])
			if err != nil {
				return err
			}
			u, err = app.Admin.SetRole(ctx, "", u.ID, args[1])
			if err != nil {
				return err
			}
			fmt.Printf("%s role=%s\n", u.Username, u.Role)
			return nil
		})
	}
	disable := userAction("disable <id|username>", "Disable a user and revoke all their sessions",
		func(ctx context.Context, app *authhttp.App, id string) (any, error) {
			u, err := app.Admin.SetDisabled(ctx, "", id, true)
			if err != nil {
				return nil, err
			}
			return map[string]any{"id": u.ID, "username": u.Username, "disabled_at": u.DisabledAt}, nil
		})
	enable := userAction("enable <id|username>", "Re-enable a disabled user",
		func(ctx context.Context, app *authhttp.App, id string) (any, error) {
			u, err := app.Admin.SetDisabled(ctx, "", id, false)
			if err != nil {
				return nil, err
			}
			return map[string]any{"id": u.ID, "username": u.Username, "disabled_at": u.DisabledAt}, nil
		})
	revoke := userAction("revoke-sessions <id|username>", "Sign a user out everywhere",
		func(ctx context.Context, app *authhttp.App, id string) (any, error) {
			n, err := app.Sessions.RevokeAll(ctx, id, "")
			return map[string]any{"revoked": n}, err
		})

	userCmd.AddCommand(userCreateCmd, userListCmd, setRole, disable, enable, revoke)
	rootCmd.AddCommand(userCmd)
}
