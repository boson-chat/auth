package commands

import (
	"context"

	"github.com/boson-chat/auth/config"
	authhttp "github.com/boson-chat/auth/http"
	"github.com/boson-chat/auth/internal/logger"
)

func loadConfig() (config.Config, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return cfg, err
	}
	logger.Logger(
		logger.WithServerName(cfg.AppConfig.APPName),
		logger.WithVersion(cfg.AppConfig.Version),
		logger.WithEnvironment(cfg.AppConfig.Env),
		logger.WithLevel(cfg.AppConfig.LogLevel),
	)
	return cfg, nil
}

// withApp builds the service for an admin command and closes it afterwards.
func withApp(ctx context.Context, fn func(ctx context.Context, app *authhttp.App) error) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	app, err := authhttp.Build(ctx, cfg, authhttp.Options{})
	if err != nil {
		return err
	}
	defer app.Close()
	return fn(ctx, app)
}
