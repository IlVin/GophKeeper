package config_test

import (
	"testing"

	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
)

func TestConfig_ErrorDefinitions(t *testing.T) {
	assert.Equal(t, "server gRPC bind address is not set", config.ErrServerBindGRPCEmpty.Error())
	assert.Equal(t, "postgres dsn is not set", config.ErrPostgresDSNEmpty.Error())
	assert.Equal(t, "server ca private key path is not set", config.ErrServerCAKeyEmpty.Error())
	assert.Equal(t, "device ca private key path is not set", config.ErrDeviceCAKeyEmpty.Error())
	assert.Equal(t, "device ca certificate path is not set", config.ErrDeviceCACertEmpty.Error())
}

func TestConfig_StructuralBinding(t *testing.T) {
	cfg := config.Config{
		Server: config.ServerConfig{
			BindGRPC: ":443",
		},
		Storage: config.StorageConfig{
			PostgresDSN: "postgres://localhost",
		},
		PKI: config.PKIConfig{
			ServerCAKeyPath: "/path/server.key",
		},
	}

	assert.Equal(t, ":443", cfg.Server.BindGRPC)
	assert.Equal(t, "postgres://localhost", cfg.Storage.PostgresDSN)
	assert.Equal(t, "/path/server.key", cfg.PKI.ServerCAKeyPath)
}
