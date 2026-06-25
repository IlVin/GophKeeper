// Package sqlite предоставляет низкоуровневые ИБ-драйверы, миграции и репозитории
// для управления зашифрованным локальным хранилищем СУБД SQLite.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
)

// Bootstrap выполняет полный сквозной цикл разворачивания локального крипто-контейнера.
//
// Функция открывает физический файл базы данных, валидирует права доступа (0600/0700),
// настраивает транзакционный режим WAL и накатывает SQL-миграции схемы таблиц.
// В случае сбоя гарантирует атомарное закрытие дескрипторов ресурсов без утечек в ОС.
func Bootstrap(path string) (*sql.DB, error) {
	slog.Debug("Initiating primary database container bootstrap procedure")

	// Открываем существующий или создаем новый файл БД с проверкой ИБ-прав доступа
	db, err := Open(path)
	if err != nil {
		slog.ErrorContext(context.Background(), "Failed to physically open database container file",
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("open SQLite container: %w", err)
	}

	// Запускаем бесшумный накат схемы миграций (таблицы device_state и records)
	if err := Migrate(db); err != nil {
		slog.ErrorContext(context.Background(), "Critical abort of SQL schema migration roll, starting descriptor cleanup",
			slog.Any("error", err),
		)

		// Явно перехватываем ошибку закрытия пула для исключения утечек в операционной системе
		if closeErr := db.Close(); closeErr != nil {
			slog.ErrorContext(context.Background(), "Critical error: database pool destructor failed on emergency exit",
				slog.Any("close_error", closeErr),
			)
			return nil, fmt.Errorf("database migration failed (%w), cascade file descriptor close failure: %w", err, closeErr)
		}

		return nil, fmt.Errorf("database table structure migration: %w", err)
	}

	slog.Debug("Local crypto storage container successfully created, table schema verified")
	return db, nil
}
