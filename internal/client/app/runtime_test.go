package app

import (
	"context"
	"testing"

	"gophkeeper/internal/client/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApp_ContextHelpersAndRuntime(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	application := NewApp(cfg, nil)
	require.NotNil(t, application)

	// Инвариант: чистый контекст не должен содержать контейнер
	_, err := AppFromContext(context.Background())
	assert.Error(t, err, "Should return an error if application is missing from context")

	// Инвариант: извлечение инжектированного контейнера из контекста
	ctx := WithApp(context.Background(), application)
	extracted, err := AppFromContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, application, extracted, "Extracted application must match the injected instance")
}
