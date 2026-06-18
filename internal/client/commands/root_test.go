package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRootCommand_Initialization(t *testing.T) {
	t.Parallel()

	v := viper.New()
	cmd, err := NewRootCommand(v)
	require.NoError(t, err)
	assert.NotNil(t, cmd)

	assert.Equal(t, "gophkeeper", cmd.Use)
	assert.NotNil(t, cmd.PersistentFlags().Lookup("config"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("ssh-auth-sock"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("sqlite-path"))
}

func TestNewRootCommand_ExecutionWithSecureFolder(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	// Явно принудительно выставляем права 0700 для прохождения внутренних проверок sqlite.go
	err := os.Chmod(tmpDir, 0700)
	require.NoError(t, err)

	dbPath := filepath.Join(tmpDir, "gophkeeper.db")

	v := viper.New()
	cmd, err := NewRootCommand(v)
	require.NoError(t, err)

	// Имитируем вызов с флагами, перенаправляющими базу в изолированную временную папку
	cmd.SetArgs([]string{"--sqlite-path", dbPath, "--ssh-auth-sock", "/tmp/mock.sock", "create", "--type", "test"})

	err = cmd.Execute()
	assert.NoError(t, err)
}
