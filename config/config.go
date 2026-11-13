// Package config holds the service configuration, loaded from env vars.
package config

import "github.com/jinzhu/configor"

type Config struct {
	AppConfig  AppConfig
	HTTPConfig HTTPConfig
}

type AppConfig struct {
	APPName  string `default:"auth"`
	Env      string `default:"development" env:"ENV"`
	Version  string `default:"dev" env:"VERSION"`
	LogLevel string `default:"info" env:"LOG_LEVEL"`
}

type HTTPConfig struct {
	// Public API listener (behind Caddy).
	Addr string `default:":8080" env:"HTTP_ADDR"`
	// Internal listener (metrics, internal API). Never expose publicly.
	InternalAddr string `default:":8081" env:"INTERNAL_ADDR"`
}

// LoadConfig reads the configuration from the environment.
func LoadConfig() (Config, error) {
	var cfg Config
	err := configor.New(&configor.Config{ENVPrefix: "-", Silent: true}).Load(&cfg)
	return cfg, err
}
