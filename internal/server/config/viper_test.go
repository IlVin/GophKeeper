package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewViper_Defaults(t *testing.T) {
	v := config.NewViper()

	assert.Equal(t, "", v.GetString("server.config_file"))
	assert.Equal(t, ":80", v.GetString("server.bind_http"))
	assert.Equal(t, ":443", v.GetString("server.bind_grpc"))
	assert.Equal(t, "", v.GetString("storage.postgres_dsn"))
	assert.Equal(t, "", v.GetString("pki.server_ca_key_path"))
}

func TestLoadFromViper_EnvironmentVariables(t *testing.T) {
	t.Setenv("GOPHKEEPER_SERVER_SERVER_BIND_GRPC", ":8443")
	t.Setenv("GOPHKEEPER_SERVER_STORAGE_POSTGRES_DSN", "postgres://user:pass@localhost/db")
	t.Setenv("GOPHKEEPER_SERVER_PKI_SERVER_CA_KEY_PATH", "/env/server.key")
	t.Setenv("GOPHKEEPER_SERVER_PKI_DEVICE_CA_KEY_PATH", "/env/device.key")
	t.Setenv("GOPHKEEPER_SERVER_PKI_DEVICE_CA_CERT_PATH", "/env/device.crt")

	v := config.NewViper()
	cfg, err := config.LoadFromViper(v)

	require.NoError(t, err)
	assert.Equal(t, ":8443", cfg.Server.BindGRPC)
	assert.Equal(t, "postgres://user:pass@localhost/db", cfg.Storage.PostgresDSN)
	assert.Equal(t, "/env/server.key", cfg.PKI.ServerCAKeyPath)
}

func TestReadConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `
server:
  bind_grpc: ":9000"
storage:
  postgres_dsn: "postgres://file:5432/db"
pki:
  server_ca_key_path: "/file/server.key"
  device_ca_key_path: "/file/device.key"
  device_ca_cert_path: "/file/device.crt"
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0600)
	require.NoError(t, err)

	v := config.NewViper()
	v.Set("server.config_file", configPath)

	err = config.ReadConfigFile(v)
	require.NoError(t, err)

	cfg, err := config.LoadFromViper(v)
	require.NoError(t, err)

	assert.Equal(t, ":9000", cfg.Server.BindGRPC)
	assert.Equal(t, "postgres://file:5432/db", cfg.Storage.PostgresDSN)
	assert.Equal(t, "/file/server.key", cfg.PKI.ServerCAKeyPath)
}
