package config_test

import (
	"testing"

	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
)

// TestConfig_Validate_Success проверяет успешную валидацию конфигурации
// и автоматическое выставление безопасных промышленных лимитов пула pgx.
func TestConfig_Validate_Success(t *testing.T) {
	cfg := &config.Config{
		Server:  config.ServerConfig{BindGRPC: ":8443"},
		Storage: config.StorageConfig{PostgresDSN: "postgres://user:pass@localhost:5432/db"},
		PKI: config.PKIConfig{
			ServerCAKeyPath: "/etc/certs/server.key",
			DeviceCAKeyPath: "/etc/certs/device.key",
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err, "Valid configuration must pass validation without errors")
	assert.Equal(t, int32(20), cfg.Storage.MaxConns, "Default max connections limit must be applied")
	assert.Equal(t, int32(2), cfg.Storage.MinConns, "Default min connections limit must be applied")
}

// TestConfig_Validate_FailsIfPostgresMissing проверяет срабатывание ИБ-барьера при пустом DSN.
func TestConfig_Validate_FailsIfPostgresMissing(t *testing.T) {
	cfg := &config.Config{
		Server:  config.ServerConfig{BindGRPC: ":8443"},
		Storage: config.StorageConfig{PostgresDSN: ""}, // Критическая пустота
		PKI: config.PKIConfig{
			ServerCAKeyPath: "/etc/certs/server.key",
			DeviceCAKeyPath: "/etc/certs/device.key",
		},
	}

	err := cfg.Validate()
	assert.ErrorIs(t, err, config.ErrPostgresDSNEmpty, "Validator must reject startup without PostgreSQL DSN")
}
