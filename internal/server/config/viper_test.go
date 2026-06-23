package config_test

import (
	"testing"

	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewViper_ShouldLoadSanitaryDefaults проверяет сборку изолированной фабрики
// и корректность наката санитарных дефолтных значений портов по умолчанию.
func TestNewViper_ShouldLoadSanitaryDefaults(t *testing.T) {
	v := config.NewViper()
	require.NotNil(t, v)

	assert.Equal(t, ":80", v.GetString("server.bind_http"))
	assert.Equal(t, ":443", v.GetString("server.bind_grpc"))
	assert.Empty(t, v.GetString("storage.postgres_dsn"))
}

// TestReadConfigFile_WithMissingExplicitFile_ShouldReturnError проверяет ИБ-барьер Fail-Fast:
// явный ненайденный файл должен вызывать ошибку, а не немой запуск.
func TestReadConfigFile_WithMissingExplicitFile_ShouldReturnError(t *testing.T) {
	v := config.NewViper()

	// Передаем заведомо несуществующий путь к файлу
	v.Set("server.config_file", "/nonexistent/path/to/gophkeeper_config_anomaly.yaml")

	err := config.ReadConfigFile(v)
	assert.ErrorIs(t, err, config.ErrExplicitConfigMissing, "Лоадер обязан выкинуть ошибку при пропаже явного файла")
}
