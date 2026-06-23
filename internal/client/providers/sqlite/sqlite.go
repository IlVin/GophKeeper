// Package sqlite предоставляет низкоуровневые ИБ-драйверы, миграции и репозитории
// для управления зашифрованным локальным хранилищем СУБД SQLite.
package sqlite

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// Open осуществляет безопасное открытие, ИБ-валидацию и низкоуровневую настройку пула СУБД SQLite.
//
// Функция проверяет права доступа 0700 на родительскую папку и 0600 на регулярный файл БД,
// открывает дескриптор, активирует режим каскадных внешних ключей и журналирование WAL.
func Open(path string) (*sql.DB, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrEmptyPath
	}

	dir := filepath.Dir(path)

	// Валидируем безопасность родительской папки контейнера
	if err := ensureParentDir(dir); err != nil {
		return nil, err
	}

	// Валидируем безопасность и тип регулярного файла контейнера СУБД
	if _, err := ensureDatabaseFile(path); err != nil {
		return nil, err
	}

	if err := validateDatabaseFile(path); err != nil {
		return nil, err
	}

	slog.Debug("Opening physical connection descriptor to SQLite container", "path", path)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database file: %w", err)
	}

	// Проверяем живой отклик СУБД до настройки внутренних прагм
	if err := db.Ping(); err != nil {
		slog.Error("SQLite storage ping failed, cascading resource closure started", "error", err)
		if closeErr := db.Close(); closeErr != nil {
			slog.Error("Cascade failure: could not close connection pool after failed ping", "close_error", closeErr)
			return nil, fmt.Errorf("database ping failed (%w), close handler failed: %w", err, closeErr)
		}
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	// Настройка ИБ и отказоустойчивости СУБД
	if err := configureSQLite(db); err != nil {
		slog.Error("SQLite pragma configuration pipeline failed, cascading connection cleanup started", "error", err)
		if closeErr := db.Close(); closeErr != nil {
			slog.Error("Cascade failure: could not close connection pool after failed pragma configuration", "close_error", closeErr)
			return nil, fmt.Errorf("database configuration failed (%w), close handler failed: %w", err, closeErr)
		}
		return nil, fmt.Errorf("database configuration failed: %w", err)
	}

	return db, nil
}

// ensureParentDir гарантирует существование директории со строгими правами 0700
func ensureParentDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Debug("Parent storage directory missing, initiating secure mkdir", "dir", dir)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("failed to create secure parent directory %q: %w", dir, err)
			}

			info, err = os.Stat(dir)
			if err != nil {
				return fmt.Errorf("failed to stat parent directory after creation %q: %w", dir, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("%w: path %q is a regular file instead of directory", ErrParentDirNotDirectory, dir)
			}
			if err := ValidateDirPermissions(dir, info); err != nil {
				return err
			}
			return nil
		}
		return fmt.Errorf("failed to verify parent directory stat %q: %w", dir, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%w: path %q is a regular file instead of directory", ErrParentDirNotDirectory, dir)
	}

	return ValidateDirPermissions(dir, info)
}

// ensureDatabaseFile гарантирует создание регулярного файла БД с ИБ-правами 0600
func ensureDatabaseFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("%w: path %q points to irregular system type", ErrDatabaseFileNotRegular, path)
		}
		return true, nil
	}

	if !os.IsNotExist(err) {
		return false, fmt.Errorf("failed to verify database file stat %q: %w", path, err)
	}

	slog.Debug("Database file missing, initiating secure atomic file initialization", "path", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, fmt.Errorf("failed to create atomic database file %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("failed to close atomic database descriptor %q: %w", path, err)
	}

	info, err = os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("failed to verify newly created database file stat %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%w: path %q points to irregular system type", ErrDatabaseFileNotRegular, path)
	}
	if err := ValidateFilePermissions(path, info); err != nil {
		return false, err
	}

	return false, nil
}

// validateDatabaseFile проверяет регулярность и маску прав существующего файла
func validateDatabaseFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to verify database file stat %q: %w", path, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: path %q points to irregular system type", ErrDatabaseFileNotRegular, path)
	}

	return ValidateFilePermissions(path, info)
}

// configureSQLite переводит пул в WAL-режим и включает Foreign Keys ограничения
func configureSQLite(db *sql.DB) error {
	// Ограничиваем пул строго 1 открытым соединением для полного исключения race conditions в SQLite файле
	db.SetMaxOpenConns(1)

	slog.Debug("Enforcing SQLite schema foreign keys integrity check constraint")
	if _, err := db.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
		return fmt.Errorf("failed to enforce sqlite foreign_keys check: %w", err)
	}

	if _, err := db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		return fmt.Errorf("failed to set sqlite busy_timeout constraint: %w", err)
	}

	slog.Debug("Enforcing SQLite secure transactional journal WAL mode")
	var journalMode string
	if err := db.QueryRow(`PRAGMA journal_mode = WAL;`).Scan(&journalMode); err != nil {
		return fmt.Errorf("failed to execute sqlite journal_mode WAL query: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("sqlite journal_mode verification mismatch: expected WAL, got %q", journalMode)
	}

	return nil
}
