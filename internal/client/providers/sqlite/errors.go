// Package sqlite предоставляет низкоуровневые ИБ-драйверы, миграции и репозитории
// для управления зашифрованным локальным хранилищем СУБД SQLite.
package sqlite

import (
	"errors"
	"log/slog"
	"os"
)

var (
	// ErrEmptyPath возвращается, если передан пустой путь к файлу контейнера СУБД.
	ErrEmptyPath = errors.New("sqlite path is empty")

	// ErrParentDirNotDirectory возвращается, если родительский путь к контейнеру указывает на обычный файл, а не на папку.
	ErrParentDirNotDirectory = errors.New("parent path is not a directory")

	// ErrParentDirInsecurePermissions возвращается, если родительская директория имеет небезопасные права доступа (требуется 0700).
	ErrParentDirInsecurePermissions = errors.New("parent directory has insecure permissions")

	// ErrDatabaseFileNotRegular возвращается, если по указанному пути базы данных обнаружен сокет, ссылка или устройство, а не регулярный файл.
	ErrDatabaseFileNotRegular = errors.New("database path is not a regular file")

	// ErrDatabaseFileInsecurePermissions возвращается, если файл контейнера СУБД имеет небезопасные права доступа в ОС (требуется 0600).
	ErrDatabaseFileInsecurePermissions = errors.New("database file has insecure permissions")
)

// LogFileSystemIncident регистрирует структурированную информацию о нарушении
// ИБ-прав доступа к файлам или директориям в скрытый лог-файл пользователя.
//
// Принимает контекстное сообщение, путь к целевому объекту и слепок os.FileInfo
// для извлечения точной маски прав доступа, зафиксированной операционной системой.
func LogFileSystemIncident(msg string, path string, info os.FileInfo) {
	if info == nil {
		slog.Error("Critical file system permissions violation tracked",
			slog.String("incident_context", msg),
			slog.String("target_path", path),
			slog.String("fs_stat", "unknown_info_nil"),
		)
		return
	}

	// Извлекаем маску прав доступа в восьмеричном формате для удобства ИБ-аудита (например, 0755)
	mode := info.Mode().Perm()

	slog.Error("Critical file system permissions violation tracked",
		slog.String("incident_context", msg),
		slog.String("target_path", path),
		slog.String("current_permissions", printfOctal(uint32(mode))),
		slog.Bool("is_directory", info.IsDir()),
	)
}

// Внутренний хелпер для форматирования прав в человекочитаемый восьмеричный вид без использования fmt
func printfOctal(mode uint32) string {
	return "0" + string(rune('0'+(mode>>6)&7)) + string(rune('0'+(mode>>3)&7)) + string(rune('0'+mode&7))
}
