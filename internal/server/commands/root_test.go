package commands_test

import (
	"testing"

	"gophkeeper/internal/server/commands"
	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewServerRootCommand_Success_FlagsVerification проверяет успешную сборку
// дерева команд сервера и корректность регистрации системных флагов в Cobra.
func TestNewServerRootCommand_Success_FlagsVerification(t *testing.T) {
	v := config.NewViper()
	serverCLI := commands.NewServerCLI(v)

	rootCmd, err := serverCLI.NewServerRootCommand()
	require.NoError(t, err)
	require.NotNil(t, rootCmd)

	// Проверяем наличие персистентных флагов в собранном объекте
	pFlags := rootCmd.PersistentFlags()
	assert.NotNil(t, pFlags.Lookup("config"), "Флаг --config должен быть зарегистрирован")
	assert.NotNil(t, pFlags.Lookup("database"), "Флаг --database должен быть зарегистрирован")
	assert.NotNil(t, pFlags.Lookup("bind-grpc"), "Флаг --bind-grpc должен быть зарегистрирован")

	// Проверяем базовые дефолты флагов
	assert.Equal(t, ":443", pFlags.Lookup("bind-grpc").DefValue)
}
