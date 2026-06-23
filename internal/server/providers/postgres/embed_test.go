package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmbed_MigrationsFS_ShouldContainCoreSchema проверяет, что виртуальная файловая
// система успешно скомпилировалась и содержит корневые файлы схем PostgreSQL.
func TestEmbed_MigrationsFS_ShouldContainCoreSchema(t *testing.T) {
	// Считываем метаданные виртуальной папки
	entries, err := migrationsFS.ReadDir("migrations")
	require.NoError(t, err, "Виртуальная директория migrations должна успешно считываться")
	require.NotEmpty(t, entries, "Папка со встроенными миграциями не должна быть пустой")

	var foundCoreSchema bool
	for _, entry := range entries {
		if entry.Name() == "00002_core_schema.sql" {
			foundCoreSchema = true
			break
		}
	}

	assert.True(t, foundCoreSchema, "Критический файл 00002_core_schema.sql обязан присутствовать в embed FS")
}
