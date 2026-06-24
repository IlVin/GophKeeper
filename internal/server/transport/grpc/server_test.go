package grpc

import (
	"crypto/tls"
	"testing"

	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewGRPCServer_Success_Compilation_Check проверяет успешное конструирование
// объекта gRPC-сервера со всеми внедренными опциями транспорта и хендлеров.
func TestNewGRPCServer_Success_Compilation_Check(t *testing.T) {
	cfg := config.Config{}

	// Создаем фиктивный пустой TLS-контекст для прохождения валидатора credentials
	dummyTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Вызываем фабрику (передаем nil пул и nil интерцептор для изоляции теста)
	server := NewGRPCServer(cfg, dummyTLSConfig, nil, nil)

	require.NotNil(t, server, "Factory must successfully return configured gRPC server object")

	t.Cleanup(func() {
		server.Stop() // Безопасно финализируем дескрипторы сервера после теста
	})

	assert.NotNil(t, server)
}
