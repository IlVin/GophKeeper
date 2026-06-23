package commands_test

import (
	"testing"

	"gophkeeper/internal/server/commands"
	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewStartCommand_Compilation_And_Name_Check проверяет корректность сборки
// фабричного метода подкоманды 'start' и её интеграцию в Cobra.
func TestNewStartCommand_Compilation_And_Name_Check(t *testing.T) {
	v := config.NewViper()
	serverCLI := commands.NewServerCLI(v)

	rootCmd, err := serverCLI.NewServerRootCommand()
	require.NoError(t, err)

	// Ищем подкоманду 'start' в зарегистрированном дереве корня
	startCmd, _, err := rootCmd.Find([]string{"start"})
	require.NoError(t, err)
	require.NotNil(t, startCmd)

	assert.Equal(t, "start", startCmd.Name(), "Имя команды должно быть строго 'start'")
	assert.NotEmpty(t, startCmd.Short, "Команда должна содержать краткое UX описание")
}
