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
	ErrDatabaseMissing = errors.New("файл базы данных не найден: пожалуйста, выполните сначала команду 'gophkeeper init'")
)

// New инициализирует, проверяет права и собирает рантайм-контейнер для уже созданного окружения.
//
// Функция выполняет fail-fast проверку наличия файла на диске, открывает безопасное
// WAL-соединение с СУБД SQLite и верифицирует его через PingContext.
func New(ctx context.Context, cfg config.Config) (*App, error) {
	slog.Debug("Запуск проверки окружения и инициализации контейнера базы данных")

	// Извлекаем путь к базе данных через каноническую цепочку иммутабельных геттеров
	sqlitePath := cfg.Storage().SQLitePath()

	// Проверяем физическое наличие файла БД перед открытием.
	if _, err := os.Stat(sqlitePath); os.IsNotExist(err) {
		slog.Error("инициализация рантайма отклонена: контейнер SQLite не создан", "path", sqlitePath)
		return nil, fmt.Errorf("%w (путь: %s)", ErrDatabaseMissing, sqlitePath)
	}

	// Открываем существующую БД. Внутренний метод sqlite.Open проверит права доступа 0600/0700.
	db, err := sqlite.Open(sqlitePath)
	if err != nil {
		slog.Error("не удалось открыть локальный контейнер хранения", "error", err)
		return nil, fmt.Errorf("открытие sqlite контейнера: %w", err)
	}

	// Проверяем живое соединение с учетом контекста прерывания сессии (Ctrl+C)
	if err := db.PingContext(ctx); err != nil {
		slog.Error("верификация соединения с SQLite провалилась", "error", err)
		if closeErr := db.Close(); closeErr != nil {
			slog.Error("не удалось закрыть дескриптор БД после неудачного пинга", "close_error", closeErr)
			return nil, fmt.Errorf("пинг базы данных (%w), закрытие дескриптора: %w", err, closeErr)
		}
		return nil, fmt.Errorf("проверка соединения с sqlite: %w", err)
	}

	slog.Debug("Локальный контейнер хранения успешно верифицирован и подключен")

	// Собираем валидированный инкапсулированный объект приложения
	application, err := NewApp(cfg, db)
	if err != nil {
		slog.Error("ошибка фабричной сборки контейнера приложения", "error", err)
		_ = db.Close()
		return nil, fmt.Errorf("сборка рантайма: %w", err)
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

	slog.Debug("Инициирован процесс остановки рантайма и очистки памяти контейнера")

	var dbErr error
	if application.db != nil {
		dbErr = application.db.Close()
		if dbErr != nil {
			slog.Error("деструктор СУБД завершился с ошибкой", "error", dbErr)
		}
		application.db = nil // Принудительно очищаем указатель на пул соединений
	}

	// Зануляем конфигурацию для предотвращения утечек путей и метаданных в оперативной памяти
	application.config = config.Config{}

	slog.Debug("Ресурсы контейнера успешно освобождены, оперативная память зачищена")
	return dbErr
}
