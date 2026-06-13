package cli

import (
	"context"
	"fmt"

	"gophkeeper/internal/config"

	"github.com/spf13/cobra"
)

type contextKey string

const configContextKey contextKey = "config"

func withConfig(ctx context.Context, cfg config.Config) context.Context {
	return context.WithValue(ctx, configContextKey, cfg)
}

func configFromContext(ctx context.Context) (config.Config, error) {
	cfg, ok := ctx.Value(configContextKey).(config.Config)
	if !ok {
		return config.Config{}, fmt.Errorf("config is missing in context")
	}

	return cfg, nil
}

func ConfigFromCommand(cmd *cobra.Command) (config.Config, error) {
	return configFromContext(cmd.Context())
}
