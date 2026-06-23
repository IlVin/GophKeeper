package certs_test

import (
	"testing"

	"gophkeeper/internal/shared/certs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadServerCAPool_Success_And_Idempotency проверяет успешный парсинг пула
// и гарантирует потокобезопасную идентичность указателей синглтона при повторных вызовах.
func TestLoadServerCAPool_Success_And_Idempotency(t *testing.T) {
	// Первый вызов (инициализирует синглтон)
	pool1, err := certs.LoadServerCAPool()
	require.NoError(t, err)
	require.NotNil(t, pool1)

	// Второй вызов (должен вернуть кэшированный экземпляр)
	pool2, err := certs.LoadServerCAPool()
	require.NoError(t, err)
	require.NotNil(t, pool2)

	// ИБ-проверка: указатели в памяти обязаны быть строго идентичными (одна аллокация в RAM)
	assert.Same(t, pool1, pool2, "Повторные вызовы лоадера пула CA обязаны возвращать кэшированный синглтон-указатель")
}

// TestLoadDeviceCAPool_Success проверяет корректность сборки пула Device CA.
func TestLoadDeviceCAPool_Success(t *testing.T) {
	pool, err := certs.LoadDeviceCAPool()
	require.NoError(t, err)
	require.NotNil(t, pool)
}
