package sqlite

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

func Open(path string) (*sql.DB, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrEmptyPath
	}

	dir := filepath.Dir(path)

	if err := ensureParentDir(dir); err != nil {
		return nil, err
	}

	if _, err := ensureDatabaseFile(path); err != nil {
		return nil, err
	}

	if err := validateDatabaseFile(path); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}

	if err := configureSQLite(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func ensureParentDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("create parent directory: %w", err)
			}

			info, err = os.Stat(dir)
			if err != nil {
				return fmt.Errorf("stat parent directory after create: %w", err)
			}
			if !info.IsDir() {
				return fmt.Errorf("%w: %s", ErrParentDirNotDirectory, dir)
			}
			if err := ValidateDirPermissions(dir, info); err != nil {
				return err
			}

			return nil
		}

		return fmt.Errorf("stat parent directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%w: %s", ErrParentDirNotDirectory, dir)
	}

	if err := ValidateDirPermissions(dir, info); err != nil {
		return err
	}

	return nil
}

func ensureDatabaseFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("%w: %s", ErrDatabaseFileNotRegular, path)
		}

		return true, nil
	}

	if !os.IsNotExist(err) {
		return false, fmt.Errorf("stat database file: %w", err)
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, fmt.Errorf("create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("close newly created database file: %w", err)
	}

	info, err = os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("stat newly created database file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%w: %s", ErrDatabaseFileNotRegular, path)
	}
	if err := ValidateFilePermissions(path, info); err != nil {
		return false, err
	}

	return false, nil
}

func validateDatabaseFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat database file: %w", err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrDatabaseFileNotRegular, path)
	}

	if err := ValidateFilePermissions(path, info); err != nil {
		return err
	}

	return nil
}

func configureSQLite(db *sql.DB) error {
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
		return fmt.Errorf("enable sqlite foreign keys: %w", err)
	}

	if _, err := db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		return fmt.Errorf("set sqlite busy_timeout: %w", err)
	}

	var journalMode string
	if err := db.QueryRow(`PRAGMA journal_mode = WAL;`).Scan(&journalMode); err != nil {
		return fmt.Errorf("set sqlite journal_mode WAL: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("set sqlite journal_mode WAL: got %q", journalMode)
	}

	return nil
}
