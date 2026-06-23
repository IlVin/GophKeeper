// Package sqlite предоставляет низкоуровневые ИБ-драйверы, миграции и репозитории
// для управления зашифрованным локальным хранилищем СУБД SQLite.
package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/pressly/goose/v3"
)

var (
	// ErrNilDatabase возвращается, если в мигратор передан пустой пул соединений.
	ErrNilDatabase = errors.New("пул соединений с базой данных не может быть nil")
)

// Migrate осуществляет контролируемый накат структуры таблиц СУБД SQLite.
//
// Функция извлекает SQL-скрипты из встроенной файловой системы MigrationsFS,
// переводит диалект в режим "sqlite" и атомарно обновляет схему до актуальной версии.
// Вывод утилиты goose в консоль полностью подавляется для защиты UX и JSON-интерфейсов.
func Migrate(db *sql.DB) error {
	// Защитный барьер предотвращает панику (nil pointer dereference) внутри goose
	if db == nil {
		slog.Error("Запрос на миграцию отклонен: передан пустой дескриптор базы данных")
		return ErrNilDatabase
	}

	slog.Debug("Старт проверки версий схемы данных и запуска мигратора Goose")

	// Намертво привязываем goose к нашей встроенной ИБ-модели файловой системы
	goose.SetBaseFS(MigrationsFS)

	// Переводим goose в бесшумный режим, защищая stdout/stderr CLI от служебного лога
	goose.SetLogger(goose.NopLogger())

	if err := goose.SetDialect("sqlite"); err != nil {
		slog.Error("Не удалось установить диалект sqlite для мигратора", "error", err)
		return fmt.Errorf("установка диалекта sqlite: %w", err)
	}

	slog.Debug("Запуск автоматического обновления таблиц device_state и records до актуального состояния")
	if err := goose.Up(db, "migrations"); err != nil {
		slog.Error("Накат SQL-миграций завершился критическим сбоем схемы", "error", err)
		return fmt.Errorf("исполнение SQL-миграций контейнера: %w", err)
	}

	slog.Debug("Схема базы данных успешно приведена к актуальной версии")
	return nil
}
