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
	assert.NotNil(t, pFlags.Lookup("config"), "--config flag must be registered")
	assert.NotNil(t, pFlags.Lookup("database"), "--database flag must be registered")
	assert.NotNil(t, pFlags.Lookup("bind-grpc"), "--bind-grpc flag must be registered")

	// Проверяем базовые дефолты флагов
	assert.Equal(t, ":443", pFlags.Lookup("bind-grpc").DefValue)
}
