package sqlite_test

import (
	"testing"

	"gophkeeper/internal/client/providers/sqlite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigrationsFS_ShouldContainCanonicalFiles проверяет целостность встроенной
// файловой системы и жестко контролирует состав SQL-миграций схемы.
func TestMigrationsFS_ShouldContainCanonicalFiles(t *testing.T) {
	// Считываем содержимое встроенной директории migrations
	entries, err := sqlite.MigrationsFS.ReadDir("migrations")
	require.NoError(t, err, "Embedded migrations directory must be readable")
	require.Len(t, entries, 2, "Embedded folder must contain exactly 2 migration files")

	// Массив ожидаемых канонических имен файлов
	expectedFiles := map[string]bool{
		"00001_init.sql":    true,
		"00002_records.sql": true,
	}

	for _, entry := range entries {
		assert.False(t, entry.IsDir(), "File system must not contain nested folders")
		assert.True(t, expectedFiles[entry.Name()], "Undocumented or third-party SQL file found in migrations: %s", entry.Name())
	}
}
