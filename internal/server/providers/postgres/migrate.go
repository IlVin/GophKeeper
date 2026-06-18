package postgres

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

const migrationsDir = "migrations"

// Migrate принимает нативный пул pgxpool.Pool, временно оборачивает его
// в совместимый stdlib-интерфейс для goose и запускает обновление схемы.
func Migrate(pool *pgxpool.Pool) error {
	if pool == nil {
		return fmt.Errorf("database pool is nil")
	}

	// Переключаем goose на работу со встроенной файловой системой сервера
	goose.SetBaseFS(migrationsFS)

	// Явно задаем диалект PostgreSQL
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect for postgres: %w", err)
	}

	// Получаем обертку *sql.DB поверх существующего пула pgxpool.
	// Это не открывает новое соединение, а использует текущий пул.
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close() // Высвобождает только дескриптор обертки, сам пул остается открытым

	// Запускаем процесс миграции
	if err := goose.Up(db, migrationsDir); err != nil {
		return fmt.Errorf("failed to run postgres server migrations: %w", err)
	}

	return nil
}
