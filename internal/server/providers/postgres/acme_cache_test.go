package postgres_test

import (
	"context"
	"testing"

	"gophkeeper/internal/server/providers/postgres"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme/autocert"
)

func TestPostgresCache_Get_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	ctx := context.Background()
	cacheKey := "test-cert-key"
	expectedData := []byte("secret-certificate-payload")

	mock.ExpectQuery(`SELECT data FROM acme_cache WHERE key = \$1`).
		WithArgs(cacheKey).
		WillReturnRows(pgxmock.NewRows([]string{"data"}).AddRow(expectedData))

	cache := postgres.NewPostgresCache(mock)
	data, err := cache.Get(ctx, cacheKey)

	require.NoError(t, err)
	assert.Equal(t, expectedData, data)
}

func TestPostgresCache_Get_CacheMiss(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	ctx := context.Background()
	cacheKey := "missing-key"

	mock.ExpectQuery(`SELECT data FROM acme_cache WHERE key = \$1`).
		WithArgs(cacheKey).
		WillReturnError(pgx.ErrNoRows)

	cache := postgres.NewPostgresCache(mock)
	_, err = cache.Get(ctx, cacheKey)

	assert.ErrorIs(t, err, autocert.ErrCacheMiss)
}

func TestPostgresCache_Put_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	ctx := context.Background()
	cacheKey := "test-cert-key"
	payload := []byte("secret-certificate-payload")

	mock.ExpectExec(`INSERT INTO acme_cache`).
		WithArgs(cacheKey, payload).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	cache := postgres.NewPostgresCache(mock)
	err = cache.Put(ctx, cacheKey, payload)

	assert.NoError(t, err)
}

func TestPostgresCache_Delete_Success(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	ctx := context.Background()
	cacheKey := "test-cert-key"

	mock.ExpectExec(`DELETE FROM acme_cache WHERE key = \$1`).
		WithArgs(cacheKey).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	cache := postgres.NewPostgresCache(mock)
	err = cache.Delete(ctx, cacheKey)

	assert.NoError(t, err)
}
