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
	require.NoError(t, err, "Встроенная директория migrations должна быть доступна для чтения")
	require.Len(t, entries, 2, "Внутри встроенной папки должно находиться строго 2 файла миграций")

	// Массив ожидаемых канонических имен файлов
	expectedFiles := map[string]bool{
		"00001_init.sql":    true,
		"00002_records.sql": true,
	}

	for _, entry := range entries {
		assert.False(t, entry.IsDir(), "Файловая система не должна содержать вложенных папок")
		assert.True(t, expectedFiles[entry.Name()], "Обнаружен недокументированный или сторонний SQL-файл в миграциях: %s", entry.Name())
	}
}
