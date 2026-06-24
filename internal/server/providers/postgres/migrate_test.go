package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMigrate_FailsIfPoolNil проверяет Fail-Fast барьер мигратора
// на попытку скормить ему неинициализированный пул.
func TestMigrate_FailsIfPoolNil(t *testing.T) {
	err := Migrate(nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database pool is nil", "Method must reject operation on nil pointer")
}
