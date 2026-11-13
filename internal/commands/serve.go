package commands

import (
	"context"
	"errors"
	nethttp "net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/boson-chat/auth/config"
	"github.com/boson-chat/auth/internal/logger"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the HTTP server",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}
		logger.Logger(
			logger.WithServerName(cfg.AppConfig.APPName),
			logger.WithVersion(cfg.AppConfig.Version),
			logger.WithEnvironment(cfg.AppConfig.Env),
		)
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		mux := nethttp.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w nethttp.ResponseWriter, _ *nethttp.Request) {
			_, _ = w.Write([]byte("ok"))
		})
		srv := &nethttp.Server{Addr: cfg.HTTPConfig.Addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		}()
		logger.FromCtx(ctx).Info().Str("addr", srv.Addr).Msg("listening")
		if err := srv.ListenAndServe(); !errors.Is(err, nethttp.ErrServerClosed) {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
