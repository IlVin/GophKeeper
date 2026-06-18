package commands

import (
	"context"
	"testing"

	clientapp "gophkeeper/internal/client/app"
	"gophkeeper/internal/client/config"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestAppFromCommand(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{Use: "test"}

	// ЯВНОЕ ИСПРАВЛЕНИЕ: Инициализируем команду базовым пустым контекстом,
	// чтобы избежать nil pointer dereference при вызове cmd.Context()
	cmd.SetContext(context.Background())

	// Теперь функция вернет чистую доменную ошибку, а не панику
	_, err := AppFromCommand(cmd)
	assert.Error(t, err, "Should fail safely if app is missing in context")

	// Успешный сценарий
	appInstance := clientapp.NewApp(config.Config{}, nil)
	ctx := clientapp.WithApp(context.Background(), appInstance)
	cmd.SetContext(ctx)

	extracted, err := AppFromCommand(cmd)
	assert.NoError(t, err)
	assert.Equal(t, appInstance, extracted, "Should successfully extract app container from command context")
}
