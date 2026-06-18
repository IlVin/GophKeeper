package commands_test

import (
	"testing"

	"gophkeeper/internal/server/commands"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServerRootCommand_FlagsRegistration(t *testing.T) {
	v := viper.New()
	cmd, err := commands.NewServerRootCommand(v)

	require.NoError(t, err)
	require.NotNil(t, cmd)

	assert.NotNil(t, cmd.PersistentFlags().Lookup("config"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("bind-grpc"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("database"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("server-ca-key"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("device-ca-key"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("device-ca-crt"))
}
