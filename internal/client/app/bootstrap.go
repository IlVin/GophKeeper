// Package app предоставляет механизмы инициализации (bootstrap) и корректной
// остановки рантайм-контейнера ресурсов GophKeeper.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"gophkeeper/internal/client/config"
	"gophkeeper/internal/client/providers/sqlite"
)

var (
	// ErrDatabaseMissing возвращается, если файл контейнера SQLite отсутствует на диске.
	ErrDatabaseMissing = errors.New("database file not found: please run .gophkeeper init. first")
)

// New инициализирует, проверяет права и собирает рантайм-контейнер для уже созданного окружения.
//
// Функция выполняет fail-fast проверку наличия файла на диске, открывает безопасное
// WAL-соединение с СУБД SQLite и верифицирует его через PingContext.
func New(ctx context.Context, cfg config.Config) (*App, error) {
	slog.Debug("Starting environment check and database container initialization")

	// Извлекаем путь к базе данных через каноническую цепочку иммутабельных геттеров
	sqlitePath := cfg.Storage().SQLitePath()

	// Проверяем физическое наличие файла БД перед открытием.
	if _, err := os.Stat(sqlitePath); os.IsNotExist(err) {
		slog.ErrorContext(ctx, "runtime initialization rejected: SQLite container not created",
			slog.String("path", sqlitePath),
		)
		return nil, fmt.Errorf("%w (путь: %s)", ErrDatabaseMissing, sqlitePath)
	}

	// Открываем существующую БД. Внутренний метод sqlite.Open проверит права доступа 0600/0700.
	db, err := sqlite.Open(sqlitePath)
	if err != nil {
		slog.ErrorContext(ctx, "failed to open local storage container",
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("open sqlite container: %w", err)
	}

	// Проверяем живое соединение с учетом контекста прерывания сессии (Ctrl+C)
	if err := db.PingContext(ctx); err != nil {
		slog.ErrorContext(ctx, "SQLite connection verification failed",
			slog.Any("error", err),
		)
		if closeErr := db.Close(); closeErr != nil {
			slog.ErrorContext(ctx, "failed to close DB descriptor after failed ping",
				slog.Any("close_error", closeErr),
			)
			return nil, fmt.Errorf("database ping (%w), closing descriptor: %w", err, closeErr)
		}
		return nil, fmt.Errorf("sqlite connection check: %w", err)
	}

	slog.Debug("Local storage container successfully verified and connected")

	// Собираем валидированный инкапсулированный объект приложения
	application, err := NewApp(cfg, db)
	if err != nil {
		slog.ErrorContext(ctx, "failed to build application container",
			slog.Any("error", err),
		)
		_ = db.Close()
		return nil, fmt.Errorf("runtime build: %w", err)
	}

	return application, nil
}

// Shutdown гарантирует безопасное закрытие файловых ресурсов СУБД и очистку RAM.
//
// Затирает ссылки на пул соединений и очищает структуру конфигурации,
// предотвращая возможность повторного использования или утечки данных из кучи.
func Shutdown(application *App) error {
	if application == nil {
		return nil
	}

	slog.Debug("Initiating runtime shutdown and container memory cleanup")

	var dbErr error
	if application.db != nil {
		dbErr = application.db.Close()
		if dbErr != nil {
			slog.ErrorContext(context.Background(), "database destructor failed",
				slog.Any("error", dbErr),
			)
		}
		application.db = nil // Принудительно очищаем указатель на пул соединений
	}

	// Зануляем конфигурацию для предотвращения утечек путей и метаданных в оперативной памяти
	application.config = config.Config{}

	slog.Debug("Container resources successfully released, memory cleared")
	return dbErr
}
