// Package sqlite предоставляет низкоуровневые ИБ-драйверы, миграции и репозитории
// для управления зашифрованным локальным хранилищем СУБД SQLite.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/pressly/goose/v3"
)

var (
	// ErrNilDatabase возвращается, если в мигратор передан пустой пул соединений.
	ErrNilDatabase = errors.New("database connection pool cannot be nil")
)

// Migrate осуществляет контролируемый накат структуры таблиц СУБД SQLite.
//
// Функция извлекает SQL-скрипты из встроенной файловой системы MigrationsFS,
// переводит диалект в режим "sqlite" и атомарно обновляет схему до актуальной версии.
// Вывод утилиты goose в консоль полностью подавляется для защиты UX и JSON-интерфейсов.
func Migrate(db *sql.DB) error {
	// Защитный барьер предотвращает панику (nil pointer dereference) внутри goose
	if db == nil {
		slog.Error("Migration request rejected: empty database descriptor provided")
		return ErrNilDatabase
	}

	slog.Debug("Starting data schema version check and Goose migrator")

	// Намертво привязываем goose к нашей встроенной ИБ-модели файловой системы
	goose.SetBaseFS(MigrationsFS)

	// Переводим goose в бесшумный режим, защищая stdout/stderr CLI от служебного лога
	goose.SetLogger(goose.NopLogger())

	if err := goose.SetDialect("sqlite"); err != nil {
		slog.ErrorContext(context.Background(), "Failed to set sqlite dialect for migrator",
			slog.Any("error", err),
		)
		return fmt.Errorf("set sqlite dialect: %w", err)
	}

	slog.Debug("Starting automatic update of device_state and records tables to current state")
	if err := goose.Up(db, "migrations"); err != nil {
		slog.ErrorContext(context.Background(), "SQL migrations roll completed with critical schema failure",
			slog.Any("error", err),
		)
		return fmt.Errorf("execute container SQL migrations: %w", err)
	}

	slog.Debug("Database schema successfully updated to current version")
	return nil
}
