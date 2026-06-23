package commands_test

import (
	"context"
	"testing"

	"gophkeeper/internal/server/app"
	"gophkeeper/internal/server/commands"
	"gophkeeper/internal/server/config"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAppFromCommand_Success проверяет успешное извлечение контейнера App
// из контекста живой Cobra-команды.
func TestAppFromCommand_Success(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}

	// Конструируем тестовый объект приложения
	originApp := app.NewApp(config.Config{}, nil, nil, nil, nil)

	// Упаковываем в контекст команды
	ctx := app.WithApp(context.Background(), originApp)
	cmd.SetContext(ctx)

	// Извлекаем через адаптер
	fetchedApp, err := commands.AppFromCommand(cmd)
	require.NoError(t, err)
	assert.Same(t, originApp, fetchedApp)
}

// TestAppFromCommand_WithNilCommand_ShouldReturnError проверяет защиту от nil указателя.
func TestAppFromCommand_WithNilCommand_ShouldReturnError(t *testing.T) {
	fetchedApp, err := commands.AppFromCommand(nil)

	assert.Error(t, err)
	assert.Nil(t, fetchedApp)
	assert.Contains(t, err.Error(), "cannot extract app container from a nil cobra command")
}
