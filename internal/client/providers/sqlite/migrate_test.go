package sqlite_test

import (
	"testing"

	"gophkeeper/internal/client/providers/sqlite"

	"github.com/stretchr/testify/assert"
)

// TestMigrate_WithNilDatabase_ShouldReturnError проверяет барьер fail-fast
// валидации мигратора при передаче пустого пула соединений.
func TestMigrate_WithNilDatabase_ShouldReturnError(t *testing.T) {
	err := sqlite.Migrate(nil)
	assert.ErrorIs(t, err, sqlite.ErrNilDatabase, "Migrator must return canonical ErrNilDatabase error on nil param")
}
