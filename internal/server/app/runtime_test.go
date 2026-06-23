package app

import (
	"context"
	"testing"

	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApp_Context_Lifecycle_ShouldSuccess проверяет сквозной цикл упаковки
// и извлечения контейнера приложения из контекста горутины.
func TestApp_Context_Lifecycle_ShouldSuccess(t *testing.T) {
	cfg := config.Config{}

	// Конструируем тестовый объект (передаем nil-ресурсы для изоляции фабрики)
	originApp := NewApp(cfg, nil, nil, nil, nil)
	require.NotNil(t, originApp)

	// Упаковываем в контекст
	ctx := WithApp(context.Background(), originApp)
	require.NotNil(t, ctx)

	// Извлекаем обратно
	fetchedApp, err := AppFromContext(ctx)
	require.NoError(t, err)
	assert.Same(t, originApp, fetchedApp, "Извлеченный из контекста объект должен быть идентичен исходному указателю")
}

// TestAppFromContext_WithEmptyContext_ShouldReturnError проверяет барьер безопасности при пустом контексте.
func TestAppFromContext_WithEmptyContext_ShouldReturnError(t *testing.T) {
	fetchedApp, err := AppFromContext(context.Background())

	assert.Error(t, err)
	assert.Nil(t, fetchedApp)
	assert.Contains(t, err.Error(), "server app runtime context container is missing")
}
