package postgres

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme/autocert"
)

// TestPostgresCache_Get_Success проверяет успешное извлечение закэшированных
// байт Let's Encrypt сертификата с использованием мок-интерфейса pgxmock.
func TestPostgresCache_Get_Success(t *testing.T) {
	// Создаем мок-пул для pgx v5
	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mockPool.Close()

	cache := NewPostgresCache(mockPool)
	ctx := context.Background()
	targetKey := "example.com"
	expectedData := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	// Настраиваем ожидания мока: СУБД должна получить SELECT и вернуть строку с байтами
	mockPool.ExpectQuery("SELECT data FROM acme_cache WHERE key = \\$1").
		WithArgs(targetKey).
		WillReturnRows(pgxmock.NewRows([]string{"data"}).AddRow(expectedData))

	// Выполняем метод
	res, err := cache.Get(ctx, targetKey)

	require.NoError(t, err)
	assert.Equal(t, expectedData, res)

	// Верифицируем, что все настроенные ожидания мока честно выполнились в рантайме
	assert.NoError(t, mockPool.ExpectationsWereMet())
}

// TestPostgresCache_Get_CacheMiss проверяет маппинг СУБД ошибки pgx.ErrNoRows на каноничную autocert.ErrCacheMiss.
func TestPostgresCache_Get_CacheMiss(t *testing.T) {
	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mockPool.Close()

	cache := NewPostgresCache(mockPool)
	ctx := context.Background()
	targetKey := "missing.com"

	// Эмулируем отсутствие строк в PostgreSQL (база пуста)
	mockPool.ExpectQuery("SELECT data FROM acme_cache WHERE key = \\$1").
		WithArgs(targetKey).
		WillReturnRows(pgxmock.NewRows([]string{"data"})) // Пустой ответ

	res, err := cache.Get(ctx, targetKey)

	assert.ErrorIs(t, err, autocert.ErrCacheMiss, "Провайдер обязан транслировать отсутствие строк в ошибку ErrCacheMiss")
	assert.Nil(t, res)
	assert.NoError(t, mockPool.ExpectationsWereMet())
}
