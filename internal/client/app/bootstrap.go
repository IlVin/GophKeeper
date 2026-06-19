package app

import (
	"context"
	"fmt"

	"gophkeeper/internal/client/config"
	"gophkeeper/internal/client/providers/sqlite"
)

func New(ctx context.Context, cfg config.Config) (*App, error) {
	_ = ctx

	db, err := sqlite.Open(cfg.Storage.SQLitePath)
	if err != nil {
		return nil, fmt.Errorf("open client sqlite: %w", err)
	}

	if err := sqlite.Migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate client sqlite: %w", err)
	}

	return NewApp(cfg, db), nil
}

func Shutdown(application *App) error {
	if application == nil || application.DB == nil {
		return nil
	}

	return application.DB.Close()
}
