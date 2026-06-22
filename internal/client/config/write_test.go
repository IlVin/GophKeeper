package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestWriteDefaultConfigFile_WithEmptyPath_ShouldDoNothing проверяет, что
// передача пустой строки в качестве пути мгновенно завершается без ошибок.
func TestWriteDefaultConfigFile_WithEmptyPath_ShouldDoNothing(t *testing.T) {
	err := WriteDefaultConfigFile("", Config{})
	assert.NoError(t, err)
}

// TestWriteDefaultConfigFile_Success проверяет успешный цикл генерации
// конфигурационного файла с проверкой выставленных прав доступа и корректности YAML-структуры.
func TestWriteDefaultConfigFile_Success(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "subfolder", "config.yaml")

	appCfg := AppConfig{defaultServer: "server.goph:8080"}
	storageCfg := StorageConfig{sqlitePath: "vault.db"}
	loggingCfg := LoggingConfig{level: "error", format: "json", logFile: "app.log"}
	cfg := NewConfig(appCfg, storageCfg, loggingCfg)

	// Выполняем запись
	err := WriteDefaultConfigFile(configPath, cfg)
	require.NoError(t, err)

	// Проверяем физическое наличие файла и его права (0600)
	info, err := os.Stat(configPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "Файл конфигурации должен иметь права строго 0600")

	// Читаем записанный файл для валидации структуры контента
	bytes, err := os.ReadFile(configPath)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = yaml.Unmarshal(bytes, &parsed)
	require.NoError(t, err)

	// Проверяем, что приватные поля успешно десериализовались через DTO слой наружу
	appMap := parsed["app"].(map[string]interface{})
	assert.Equal(t, "server.goph:8080", appMap["default_server"])

	storageMap := parsed["storage"].(map[string]interface{})
	assert.Equal(t, "vault.db", storageMap["sqlite_path"])
}

// TestWriteDefaultConfigFile_FileAlreadyExists_ShouldNotOverwrite проверяет,
// что если файл уже существует, функция не затрет пользовательские настройки.
func TestWriteDefaultConfigFile_FileAlreadyExists_ShouldNotOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "existing_config.yaml")

	originalContent := []byte("custom_user_option: true")
	err := os.WriteFile(configPath, originalContent, 0o600)
	require.NoError(t, err)

	// Пытаемся вызвать запись дефолтов поверх существующего файла
	cfg := NewConfig(AppConfig{}, StorageConfig{}, LoggingConfig{})
	err = WriteDefaultConfigFile(configPath, cfg)
	assert.NoError(t, err)

	// Проверяем, что содержимое файла не изменилось
	currentContent, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, originalContent, currentContent, "Функция не должна перезаписывать существующий файл")
}
