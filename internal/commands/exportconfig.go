package commands

import (
	"os"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/db"
	settingsrepo "github.com/boson-chat/auth/internal/db/repositories/settings"
	auditsvc "github.com/boson-chat/auth/internal/services/audit"
	"github.com/boson-chat/auth/internal/services/settings"
	"github.com/spf13/cobra"
)

var exportConfigCmd = &cobra.Command{
	Use:   "export-config",
	Short: "Print the network: and auth: sections of the stack config file from the current env and database",
	Long: `Prints YAML for config/boson.yaml built from the env values and the
network_settings table (the values the admin panel set before the config
file existed). The config file itself (BOSON_CONFIG) is not read. Merge the
output into config/boson.yaml once when moving an install to the file.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		ctx := cmd.Context()
		database, err := db.NewDatabase(ctx, cfg.DBConfig)
		if err != nil {
			return err
		}
		defer database.Close()
		svc := settings.NewSettingsService(settingsrepo.NewSettingsRepository(database), database,
			auditsvc.NewAuditService(nil), cfg.AccountConfig, nil)
		st, err := svc.Get(ctx)
		if err != nil {
			return err
		}
		a := &cfg.AccountConfig
		a.Registration, a.RequireEmailVerification, a.GuestAccess, a.GuestVoice = st.Registration, st.RequireEmailVerification, st.GuestAccess, st.GuestVoice
		a.ChannelCreation, a.VoiceChannelCreation = st.ChannelCreation, st.VoiceChannelCreation
		a.ChannelAutoRegister, a.ChannelExpiryDays = st.ChannelAutoRegister, st.ChannelExpiryDays
		out, err := config.ExportFile(cfg, os.Getenv("CORS_ALLOWED_ORIGINS") != "")
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(out)
		return err
	},
}

func init() {
	rootCmd.AddCommand(exportConfigCmd)
}
