package commands

import (
	"bytes"
	"context"
	"testing"

	serverapp "gophkeeper/internal/server/app"
	"gophkeeper/internal/server/config"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStopCommand_ExecutionShortcut(t *testing.T) {
	var cfg config.Config
	cfg.Server.BindGRPC = ":443"
	cfg.Storage.PostgresDSN = "mock-dsn"

	application := serverapp.NewApp(cfg, nil, nil, nil)

	ctx := context.Background()
	ctx = serverapp.WithApp(ctx, application)

	v := viper.New()
	root, err := NewServerRootCommand(v)
	require.NoError(t, err)

	// Отключаем автоматический запуск полного Bootstrap в PreRun для этого изолированного CLI-теста,
	// так как мы уже вручную подготовили mock-контекст приложения выше.
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return nil
	}

	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetContext(ctx)
	root.SetArgs([]string{"stop"})

	err = root.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "triggering context-bound graceful shutdown...")
}
