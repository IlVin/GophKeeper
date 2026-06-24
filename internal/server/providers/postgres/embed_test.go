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
	require.NoError(t, err, "Virtual migrations directory must be readable")
	require.NotEmpty(t, entries, "Embedded migrations folder must not be empty")

	var foundCoreSchema bool
	for _, entry := range entries {
		if entry.Name() == "00002_core_schema.sql" {
			foundCoreSchema = true
			break
		}
	}

	assert.True(t, foundCoreSchema, "Critical file 00002_core_schema.sql must be present in embed FS")
}
