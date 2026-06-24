package sqlite_test

import (
	"os"
	"path/filepath"
	"testing"

	"gophkeeper/internal/client/providers/sqlite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBootstrap_Success проверяет успешный сквозной цикл разворачивания базы данных.
// Тестирует физическое создание файла, накат таблиц и проверку доступности дескриптора.
func TestBootstrap_Success(t *testing.T) {
	tmpDir := t.TempDir()

	// Принудительно выставляем жесткие ИБ-права 0700 на временную папку для прохождения проверок Open()
	err := os.Chmod(tmpDir, 0o700)
	require.NoError(t, err)

	dbPath := filepath.Join(tmpDir, "gophkeeper_bootstrap_test.db")

	// Запускаем bootstrap
	db, err := sqlite.Bootstrap(dbPath)
	require.NoError(t, err, "Database bootstrap procedure should complete successfully")
	require.NotNil(t, db, "Database connection pool pointer should not be nil")

	defer func() {
		_ = db.Close()
	}()

	// Проверяем живое соединение с базой данных
	err = db.Ping()
	assert.NoError(t, err, "Created database must successfully respond to runtime ping")

	// Проверяем, что таблицы физически создались в схеме
	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='records';").Scan(&tableName)
	require.NoError(t, err, "records table must exist in created data schema")
	assert.Equal(t, "records", tableName)
}

// TestBootstrap_WithInvalidPath_ShouldReturnError проверяет срабатывание fail-fast
// барьера при передаче заведомо некорректного пути к файлу базы данных.
func TestBootstrap_WithInvalidPath_ShouldReturnError(t *testing.T) {
	// Передаем путь к несуществующей директории без прав доступа
	db, err := sqlite.Bootstrap("/invalid/nonexistent/directory/structure/vault.db")

	assert.Error(t, err, "Attempt to create container at invalid path must return error")
	assert.Nil(t, db, "On initialization error database pool pointer must be nil")
}
