package app

import (
	"context"
	"fmt"

	"gophkeeper/internal/client/config"
	"gophkeeper/internal/client/providers/sqlite"

	"github.com/spf13/viper"
)

func Bootstrap(ctx context.Context, v *viper.Viper) (context.Context, *App, error) {
	if err := config.ReadConfigFile(v); err != nil {
		return ctx, nil, fmt.Errorf("read client config: %w", err)
	}

	cfg, err := config.LoadFromViper(v)
	if err != nil {
		return ctx, nil, fmt.Errorf("load config: %w", err)
	}

	db, err := sqlite.Open(cfg.Storage.SQLitePath)
	if err != nil {
		return ctx, nil, fmt.Errorf("open client sqlite: %w", err)
	}

	if err := sqlite.Migrate(db); err != nil {
		_ = db.Close()
		return ctx, nil, fmt.Errorf("migrate client sqlite: %w", err)
	}

	application := NewApp(cfg, db)
	ctx = WithApp(ctx, application)

	return ctx, application, nil
}

func Shutdown(application *App) error {
	if application == nil || application.DB == nil {
		return nil
	}

	return application.DB.Close()
}
