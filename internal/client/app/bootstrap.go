package app

import (
	"context"
	"fmt"
	"os"

	"gophkeeper/internal/client/config"
	"gophkeeper/internal/client/providers/sqlite"
)

// New собирает runtime-контейнер только для уже инициализированного окружения
func New(ctx context.Context, cfg config.Config) (*App, error) {
	// Проверяем физическое наличие файла БД перед открытием.
	// Если файла нет — значит пользователь не запускал 'gophkeeper init'.
	if _, err := os.Stat(cfg.Storage.SQLitePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("database file missing: please run 'gophkeeper init' first")
	}

	// Открываем существующую БД. Open() сам проверит права доступа 0600/0700.
	db, err := sqlite.Open(cfg.Storage.SQLitePath)
	if err != nil {
		return nil, fmt.Errorf("open client sqlite: %w", err)
	}

	// Проверяем живое соединение с учетом контекста прерывания
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping client sqlite: %w", err)
	}

	// Миграции отсюда УБРАНЫ. Они выполняются строго один раз внутри 'gophkeeper init'.

	return NewApp(cfg, db), nil
}

// Shutdown гарантирует безопасное закрытие ресурсов и зануление ссылок
func Shutdown(application *App) error {
	if application == nil {
		return nil
	}

	var dbErr error
	if application.DB != nil {
		dbErr = application.DB.Close()
		application.DB = nil // Очищаем указатель
	}

	// Зануляем конфигурацию для предотвращения утечек данных в RAM
	application.Config = config.Config{}

	return dbErr
}
