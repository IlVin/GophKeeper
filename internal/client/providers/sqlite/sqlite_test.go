package sqlite

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpen_CreatesDatabaseFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "state", "goph_keeper.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected database file to exist: %v", err)
	}
}

func TestOpen_RejectsEmptyPath(t *testing.T) {
	_, err := Open("")
	if !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("Open() error = %v, want %v", err, ErrEmptyPath)
	}
}

func TestOpen_ConfiguresSQLitePragmas(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "state", "goph_keeper.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	var foreignKeys int
	if err := db.QueryRow(`PRAGMA foreign_keys;`).Scan(&foreignKeys); err != nil {
		t.Fatalf("query PRAGMA foreign_keys error = %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("PRAGMA foreign_keys = %d, want 1", foreignKeys)
	}

	var busyTimeout int
	if err := db.QueryRow(`PRAGMA busy_timeout;`).Scan(&busyTimeout); err != nil {
		t.Fatalf("query PRAGMA busy_timeout error = %v", err)
	}
	if busyTimeout != 5000 {
		t.Fatalf("PRAGMA busy_timeout = %d, want 5000", busyTimeout)
	}

	var journalMode string
	if err := db.QueryRow(`PRAGMA journal_mode;`).Scan(&journalMode); err != nil {
		t.Fatalf("query PRAGMA journal_mode error = %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("PRAGMA journal_mode = %q, want %q", journalMode, "wal")
	}
}

func TestMigrate_RunsMigrations(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "state", "goph_keeper.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	if !tableExists(t, db, "device_state") {
		t.Fatal("expected table device_state to exist after migration")
	}
}

func TestMigrate_IsIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "state", "goph_keeper.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	if err := Migrate(db); err != nil {
		t.Fatalf("first Migrate() error = %v", err)
	}

	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}

	if !tableExists(t, db, "device_state") {
		t.Fatal("expected table device_state to exist after repeated migration")
	}
}

func tableExists(t *testing.T, db *sql.DB, tableName string) bool {
	t.Helper()

	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, tableName).Scan(&name)
	if err != nil {
		return false
	}

	return name == tableName
}
