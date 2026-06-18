package postgres_test

import (
	"testing"

	"gophkeeper/internal/server/providers/postgres"

	"github.com/stretchr/testify/assert"
)

func TestMigrate_NilPoolError(t *testing.T) {
	err := postgres.Migrate(nil)
	assert.ErrorContains(t, err, "database pool is nil")
}
