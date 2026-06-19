package app

import (
	"database/sql"

	"gophkeeper/internal/client/config"
)

type App struct {
	Config config.Config
	DB     *sql.DB
}

func NewApp(cfg config.Config, db *sql.DB) *App {
	return &App{
		Config: cfg,
		DB:     db,
	}
}
