package commands_test

import (
	"bytes"
	"testing"

	"gophkeeper/internal/server/commands"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartCommand_MissingContextError(t *testing.T) {
	v := viper.New()
	root, err := commands.NewServerRootCommand(v)
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetArgs([]string{"start"})

	// Запуск должен упасть, так как Bootstrap не выполнился из-за отсутствия конфигурации
	err = root.Execute()
	assert.Error(t, err)
}
