package postgres_test

import (
	"context"
	"testing"

	"gophkeeper/internal/server/config"
	"gophkeeper/internal/server/providers/postgres"

	"github.com/stretchr/testify/assert"
)

func TestConnect_EmptyDSNError(t *testing.T) {
	ctx := context.Background()
	var cfg config.StorageConfig
	cfg.PostgresDSN = ""

	pool, err := postgres.Connect(ctx, cfg)
	assert.ErrorContains(t, err, "postgres dsn configuration is empty")
	assert.Nil(t, pool)
}

func TestConnect_MalformedDSNError(t *testing.T) {
	ctx := context.Background()
	var cfg config.StorageConfig
	cfg.PostgresDSN = "postgres://invalid-user:password-with-bad-chars-%%@localhost:5432/db"

	pool, err := postgres.Connect(ctx, cfg)
	assert.Error(t, err)
	assert.Nil(t, pool)
}
