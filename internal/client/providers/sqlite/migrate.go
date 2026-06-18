package sqlite

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/pressly/goose/v3"
)

var ErrNilDatabase = errors.New("database connection pool is nil")

func Migrate(db *sql.DB) error {
	// ДОБАВЛЕНО: Защитный блок предотвращает nil pointer панику внутри goose
	if db == nil {
		return ErrNilDatabase
	}

	goose.SetBaseFS(migrationsFS)

	if err := goose.SetDialect("sqlite"); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}

	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("run client sqlite migrations: %w", err)
	}

	return nil
}
