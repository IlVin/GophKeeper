package sqlite_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gophkeeper/internal/client/providers/sqlite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpen_WithEmptyPath_ShouldReturnError проверяет fail-fast барьер ядра на пустой путь.
func TestOpen_WithEmptyPath_ShouldReturnError(t *testing.T) {
	db, err := sqlite.Open("  ")
	assert.ErrorIs(t, err, sqlite.ErrEmptyPath)
	assert.Nil(t, db)
}

// TestOpen_Success_And_PragmaVerification проверяет успешный цикл создания и открытия
// базы данных со строгой валидацией PRAGMA-параметров (WAL, Foreign Keys) на диске.
func TestOpen_Success_And_PragmaVerification(t *testing.T) {
	tmpDir := t.TempDir()

	// Принудительно выставляем жесткие ИБ-права 0700 на временную папку
	err := os.Chmod(tmpDir, 0o700)
	require.NoError(t, err)

	dbPath := filepath.Join(tmpDir, "production_vault.db")

	// Открываем базу через ядро Open
	db, err := sqlite.Open(dbPath)
	require.NoError(t, err, "Secure database open must succeed")
	require.NotNil(t, db)

	defer func() {
		_ = db.Close()
	}()

	// 1. Верифицируем, что PRAGMA foreign_keys успешно применилась и активна (выдаст 1)
	var foreignKeysEnabled int
	err = db.QueryRow("PRAGMA foreign_keys;").Scan(&foreignKeysEnabled)
	require.NoError(t, err)
	assert.Equal(t, 1, foreignKeysEnabled, "Database foreign key constraint must be forcibly enabled")

	// 2. Верифицируем, что PRAGMA journal_mode на диске честно переведена в WAL
	var currentJournalMode string
	err = db.QueryRow("PRAGMA journal_mode;").Scan(&currentJournalMode)
	require.NoError(t, err)
	assert.Equal(t, "wal", strings.ToLower(currentJournalMode), "Transaction journaling must work in WAL mode")
}
