package commands

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"github.com/boson-chat/auth/db"
	authhttp "github.com/boson-chat/auth/http"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/boson-chat/auth/metrics"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the public and internal HTTP listeners",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		log := logger.FromCtx(ctx)

		if cfg.DBConfig.AutoMigrate {
			if err := db.MigrateUp(cfg.DBConfig.DSN()); err != nil {
				return err
			}
			log.Info().Msg("migrations up to date")
		}

		mp, err := metrics.NewProvider(ctx, cfg)
		if err != nil {
			return err
		}
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = mp.Shutdown(sctx)
		}()
		m, err := metrics.New(mp.MeterProvider())
		if err != nil {
			return err
		}

		app, err := authhttp.Build(ctx, cfg, authhttp.Options{Metrics: m, MetricsHandler: mp.Handler()})
		if err != nil {
			return err
		}
		defer app.Close()
		if err := app.Keys.Ensure(ctx); err != nil {
			return err
		}
		if app.Workload != nil {
			if err := app.Workload.Keys.Ensure(ctx); err != nil {
				return err
			}
			log.Info().Str("issuer", app.Workload.Issuer()).Msg("workload issuer on (WORKLOAD_IDENTITIES)")
		}
		if cfg.SMTPConfig.Host == "" {
			log.Warn().Msg("SMTP_HOST is empty: emails are logged, not sent (dev only)")
		}
		if cfg.InternalConfig.APIToken == "" {
			log.Warn().Msg("INTERNAL_API_TOKEN is empty: /internal/v1 is disabled")
		}
		app.RunBackground(ctx)
		return authhttp.Serve(ctx, app)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
