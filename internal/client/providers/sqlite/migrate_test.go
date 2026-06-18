package sqlite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMigrate_NilDatabaseError(t *testing.T) {
	err := Migrate(nil)
	assert.Error(t, err)
}
