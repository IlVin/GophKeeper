package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewViper_ShouldSetCorrectDefaults проверяет, что конструктор NewViper
// корректно инициализирует объект Viper и прописывает базовые санитарные дефолты.
func TestNewViper_ShouldSetCorrectDefaults(t *testing.T) {
	v, err := NewViper()
	require.NoError(t, err)
	require.NotNil(t, v)

	assert.Equal(t, "info", v.GetString("logging.level"))
	assert.Equal(t, "text", v.GetString("logging.format"))
	assert.Equal(t, "localhost:443", v.GetString("app.default_server"))
}

// TestReadConfigFile_WithNonExistentExplicitPath_ShouldNotReturnError проверяет,
// что утилита не падает, если явно указанный конфигурационный файл физически отсутствует на диске.
func TestReadConfigFile_WithNonExistentExplicitPath_ShouldNotReturnError(t *testing.T) {
	v, err := NewViper()
	require.NoError(t, err)

	v.Set("app.config_file", "/non/existent/path/to/config.yaml")

	err = ReadConfigFile(v)
	assert.NoError(t, err, "Missing file on disk should not cause runtime errors")
}

// TestLoadFromViper_WithValidData_ShouldAssembleConfig проверяет сквозную сборку
// инкапсулированного объекта Config на основе данных из Viper.
func TestLoadFromViper_WithValidData_ShouldAssembleConfig(t *testing.T) {
	v, err := NewViper()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	expectedDBPath := filepath.Join(tmpDir, "goph.db")

	v.Set("storage.sqlite_path", expectedDBPath)
	v.Set("logging.level", "error")

	cfg, err := LoadFromViper(v)
	require.NoError(t, err, "Building valid params should succeed")

	assert.Equal(t, expectedDBPath, cfg.Storage().SQLitePath())
	assert.Equal(t, "error", cfg.Logging().Level())
}

// TestReadConfigFile_WithCorruptedYaml_ShouldReturnError проверяет генерацию ошибки
// в случае, если файл конфигурации поврежден или имеет невалидный синтаксис.
func TestReadConfigFile_WithCorruptedYaml_ShouldReturnError(t *testing.T) {
	v, err := NewViper()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	corruptedFile := filepath.Join(tmpDir, "corrupted.yaml")

	// Пишем ломаный YAML синтаксис
	err = os.WriteFile(corruptedFile, []byte("app:\n  config_file: [broken json string"), 0o600)
	require.NoError(t, err)

	v.Set("app.config_file", corruptedFile)

	err = ReadConfigFile(v)
	assert.Error(t, err, "Reading corrupted YAML file should return parse error")
}
