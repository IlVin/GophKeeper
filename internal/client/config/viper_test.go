package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewViper_Defaults(t *testing.T) {
	t.Parallel()

	v := NewViper()
	assert.Equal(t, "", v.GetString("app.config_file"))
	assert.Equal(t, "", v.GetString("ssh_agent.socket_path"))
	assert.NotEmpty(t, v.GetString("storage.sqlite_path"))
}

func TestReadConfigFile_Behavior(t *testing.T) {
	t.Parallel()

	t.Run("empty configuration path does nothing", func(t *testing.T) {
		t.Parallel()
		v := NewViper()
		err := ReadConfigFile(v)
		assert.NoError(t, err)
	})

	t.Run("valid configuration file parses successfully", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "config.yaml")

		yamlContent := []byte("ssh_agent:\n  socket_path: /custom/ssh.sock\n")
		err := os.WriteFile(cfgPath, yamlContent, 0600)
		require.NoError(t, err)

		v := NewViper()
		v.Set("app.config_file", cfgPath)

		err = ReadConfigFile(v)
		require.NoError(t, err)
		assert.Equal(t, "/custom/ssh.sock", v.GetString("ssh_agent.socket_path"))
	})
}

func TestLoadFromViper_FallbackAndValidation(t *testing.T) {
	// Очищаем или подменяем env переменные, параллельность отключаем во избежание гонок за os.Environ
	origSSHAuthSock := os.Getenv("SSH_AUTH_SOCK")
	defer func() { _ = os.Setenv("SSH_AUTH_SOCK", origSSHAuthSock) }()

	t.Run("successful fallback to system SSH_AUTH_SOCK", func(t *testing.T) {
		_ = os.Setenv("SSH_AUTH_SOCK", "/system/env/ssh.sock")

		v := viper.New()
		v.Set("storage.sqlite_path", "/tmp/valid.db")
		v.Set("ssh_agent.socket_path", "") // Оставляем пустым для триггера фолбека

		cfg, err := LoadFromViper(v)
		require.NoError(t, err)
		assert.Equal(t, "/system/env/ssh.sock", cfg.SSHAgent.SocketPath)
	})
}

func TestDefaultSQLitePathFromFunc(t *testing.T) {
	t.Parallel()

	mockFunc := func(rel string) (string, error) {
		return "/mock/xdg/path/" + rel, nil
	}

	path := defaultSQLitePathFromFunc(mockFunc)
	assert.Equal(t, "/mock/xdg/path/gophkeeper/goph_keeper.db", path)
}
