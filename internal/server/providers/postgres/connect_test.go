package postgres

import (
	"context"
	"testing"

	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
)

// TestConnect_FailsIfDsnEmpty проверяет Fail-Fast барьер лоадера соединений,
// если в метод передана пустая DSN-строка.
func TestConnect_FailsIfDsnEmpty(t *testing.T) {
	ctx := context.Background()
	emptyConfig := config.StorageConfig{
		PostgresDSN: "", // Пустое поле
	}

	pool, err := Connect(ctx, emptyConfig)

	assert.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "postgres dsn configuration string is empty")
}
