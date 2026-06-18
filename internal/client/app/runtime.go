package app

import (
	"context"
	"database/sql"
	"fmt"

	"gophkeeper/internal/client/config"
)

type App struct {
	Config config.Config
	DB     *sql.DB
}

type contextKey string

const appContextKey contextKey = "app"

func NewApp(cfg config.Config, db *sql.DB) *App {
	return &App{
		Config: cfg,
		DB:     db,
	}
}

func WithApp(ctx context.Context, application *App) context.Context {
	return context.WithValue(ctx, appContextKey, application)
}

func AppFromContext(ctx context.Context) (*App, error) {
	// Добавляем защиту от nil-контекста
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}

	application, ok := ctx.Value(appContextKey).(*App)
	if !ok || application == nil {
		return nil, fmt.Errorf("app is missing in context")
	}

	return application, nil
}
