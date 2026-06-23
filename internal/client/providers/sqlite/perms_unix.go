//go:build unix

// Package sqlite предоставляет низкоуровневые ИБ-драйверы, миграции и репозитории
// для управления зашифрованным локальным хранилищем СУБД SQLite.
package sqlite

import (
	"fmt"
	"os"
)

// ValidateDirPermissions проверяет, что родительская директория крипто-контейнера
// имеет строгие ИБ-права доступа 0700 (чтение, запись, исполнение только владельцу).
//
// В случае несоответствия фиксирует инцидент безопасности в системный лог-файл
// и возвращает каноничную ошибку ErrParentDirInsecurePermissions на английском языке.
func ValidateDirPermissions(path string, info os.FileInfo) error {
	mode := info.Mode().Perm()
	if mode != 0o700 {
		// Фиксируем ИБ-инцидент нарушения прав доступа в скрытый лог-файл сессии
		LogFileSystemIncident("insecure parent directory permissions detected", path, info)

		return fmt.Errorf("%w: path %q has permissions %04o, expected 0700",
			ErrParentDirInsecurePermissions, path, mode)
	}
	return nil
}

// ValidateFilePermissions проверяет, что физический файл базы данных SQLite
// имеет строгие ИБ-права доступа 0600 (чтение и запись только владельцу).
//
// В случае обнаружения избыточных прав фиксирует инцидент в системный лог
// и возвращает каноничную ошибку ErrDatabaseFileInsecurePermissions на английском языке.
func ValidateFilePermissions(path string, info os.FileInfo) error {
	mode := info.Mode().Perm()
	if mode != 0o600 {
		// Фиксируем ИБ-инцидент нарушения прав доступа к зашифрованному контейнеру СУБД
		LogFileSystemIncident("insecure database file permissions detected", path, info)

		return fmt.Errorf("%w: file %q has permissions %04o, expected 0600",
			ErrDatabaseFileInsecurePermissions, path, mode)
	}
	return nil
}
