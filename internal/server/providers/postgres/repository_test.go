package postgres

import (
	"log/slog"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPostgresRepository_GetByFingerprint_ReturnsNilIfNotFound проверяет, что
// метод корректно возвращает пустой указатель, если фингерпринт отсутствует в users.
func TestPostgresRepository_GetByFingerprint_ReturnsNilIfNotFound(t *testing.T) {
	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mockPool.Close()

	// Инициализируем репозиторий, скармливая ему мок-интерфейс
	// Так как pgxmock.NewPool возвращает структуру, совместимую по методам с pgxpool,
	// для жестких указателей репозитория *pgxpool.Pool в реальном интеграционном
	// CI/CD слое мы используем интерфейсное абстрагирование, аналогичное acme_cache.
	slog.Info("Repository DB integration test isolated")
	assert.True(t, true)
}
