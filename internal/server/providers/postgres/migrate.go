// Package postgres предоставляет реализации инфраструктурных адаптеров,
// репозиториев и кэш-провайдеров для взаимодействия с СУБД PostgreSQL.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

const migrationsDir = "migrations"

// Migrate принимает нативный пул pgxpool.Pool, адаптирует его под stdlib-интерфейс
// и выполняет пошаговый накат встроенных SQL-миграций ядра (Goose Up).
//
// Функция полностью автономна и изолирована в рамках виртуальной migrationsFS,
// гарантируя стабильность разворачивания схем данных в Docker/K8s кластерах.
func Migrate(pool *pgxpool.Pool) error {
	if pool == nil {
		slog.Error("Database migration aborted: provided postgres connection pool is nil")
		return errors.New("database pool is nil")
	}

	slog.Info("Initiating automated server database schemas evolutionary upgrade phase")

	// Переключаем goose на работу со встроенной виртуальной файловой системой сервера (embed)
	goose.SetBaseFS(migrationsFS)

	// Явно фиксируем диалект PostgreSQL
	if err := goose.SetDialect("postgres"); err != nil {
		slog.ErrorContext(context.Background(), "Failed to set strict goose dialect for postgres engine",
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to set goose dialect for postgres: %w", err)
	}

	// Получаем sql.DB обертку поверх существующего пула без открытия новых TCP-сессий
	db := stdlib.OpenDBFromPool(pool)

	defer func() {
		slog.Debug("Closing virtual stdlib sql.DB wrap layer descriptor")
		if closeErr := db.Close(); closeErr != nil {
			slog.ErrorContext(context.Background(), "Failed to cleanly dispose virtual stdlib sql.DB wrap layer",
				slog.Any("error", closeErr),
			)
		}
	}()

	// Запускаем процесс миграции (накатывает все новые *.sql файлы до актуальной версии)
	slog.Debug("Executing goose.Up migration path sequence mapping",
		slog.String("dir", migrationsDir),
	)
	if err := goose.Up(db, migrationsDir); err != nil {
		slog.ErrorContext(context.Background(), "Critical database migrations apply collapse tracked",
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to run postgres server migrations: %w", err)
	}

	slog.Info("Server database schemas evolutionary upgrade successfully synchronized and finalized")
	return nil
}
