package grpc

import (
	"crypto/tls"
	"testing"

	"gophkeeper/internal/server/config"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestNewGRPCServer_InitializationSuccess(t *testing.T) {
	var cfg config.Config

	// Готовим минимальную конфигурацию TLS 1.3
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Инициализируем пустую заглушку пула, так как серверу важна только проверка на nil
	var mockPool *pgxpool.Pool

	// Запускаем сборку gRPC сервера
	server := NewGRPCServer(cfg, tlsConfig, mockPool)

	require.NotNil(t, server)

	// Проверяем, что объект gRPC-сервера успешно сконструирован и готов к прослушиванию сокетов
	assert.IsType(t, &grpc.Server{}, server)
}
