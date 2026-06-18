package commands

import (
	"bytes"
	"context"
	"testing"

	clientapp "gophkeeper/internal/client/app"
	"gophkeeper/internal/client/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCreateCommand_Execution(t *testing.T) {
	t.Parallel()

	cmd := newCreateCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	// Инициализируем фейковый контекст приложения
	cfg := config.Config{}
	cfg.App.ConfigFile = "test.yaml"
	cfg.SSHAgent.SocketPath = "/tmp/ssh.sock"
	cfg.Storage.SQLitePath = "/tmp/test.db"

	appInstance := clientapp.NewApp(cfg, nil)
	ctx := clientapp.WithApp(context.Background(), appInstance)
	cmd.SetContext(ctx)

	cmd.SetArgs([]string{"--type", "password", "--key", "github", "--value", "secret123"})
	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "config file: test.yaml")
	assert.Contains(t, output, "type: password")
	assert.Contains(t, output, "key: github")
	assert.Contains(t, output, "value: secret123")
}
