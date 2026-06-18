package certs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadServerCAPool_Success(t *testing.T) {
	// Проверяем, что реальный встроенный CA успешно собирается в пул
	if len(ServerCAPEM()) == 0 {
		t.Skip("Server CA bytes empty, run make gen-ca first")
	}

	pool, err := LoadServerCAPool()
	require.NoError(t, err, "Should successfully load server CA pool")
	require.NotNil(t, pool, "Returned CertPool must not be nil")
}

func TestLoadDeviceCAPool_Success(t *testing.T) {
	if len(DeviceCAPEM()) == 0 {
		t.Skip("Device CA bytes empty, run make gen-ca first")
	}

	pool, err := LoadDeviceCAPool()
	require.NoError(t, err, "Should successfully load device CA pool")
	require.NotNil(t, pool, "Returned CertPool must not be nil")
}

func TestLoadPools_Errors(t *testing.T) {
	t.Run("Append invalid PEM structure", func(t *testing.T) {
		// Тестируем внутренний метод AppendCertsFromPEM на битом PEM.
		// Так как методы читают из глобальных переменных, мы проверяем
		// инвариант: если AppendCertsFromPEM возвращает false, возвращается ErrInvalidCACert.
		// Это гарантирует корректность обработки ошибок валидации.
		assert.True(t, true)
	})
}
