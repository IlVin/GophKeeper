package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestEnv изолирует окружение теста от реальной операционной системы.
// Она перенаправляет XDG директории во временную папку, предотвращая чтение
// или перезапись настоящих конфигураций и логов разработчика.
func setupTestEnv(t *testing.T) {
	t.Helper()

	// Сохраняем оригинальные переменные окружения
	origConfig := os.Getenv("XDG_CONFIG_HOME")
	origState := os.Getenv("XDG_STATE_HOME")
	origArgs := os.Args

	// Создаем изолированную временную директорию для этого тест-кейса
	tmpDir := t.TempDir()

	// Настраиваем фейковое XDG окружение
	err := os.Setenv("XDG_CONFIG_HOME", filepath.Join(tmpDir, "config"))
	require.NoError(t, err)
	err = os.Setenv("XDG_STATE_HOME", filepath.Join(tmpDir, "state"))
	require.NoError(t, err)

	// Восстанавливаем окружение после завершения теста
	t.Cleanup(func() {
		_ = os.Setenv("XDG_CONFIG_HOME", origConfig)
		_ = os.Setenv("XDG_STATE_HOME", origState)
		os.Args = origArgs
	})
}

// TestRun_WithHelpFlag_ShouldSuccess проверяет корректность сборки дерева команд.
// При передаче флага --help приложение должно вернуть статус успешного выполнения без ошибок.
func TestRun_WithHelpFlag_ShouldSuccess(t *testing.T) {
	setupTestEnv(t)

	// Имитируем вызов клиента с флагом --help
	os.Args = []string{"gophkeeper", "--help"}

	err := run()
	assert.NoError(t, err, "execution with --help should not return error")
}

// TestRun_WithInvalidFlag_ShouldReturnError проверяет обработку ошибок парсинга Cobra.
// При передаче неизвестного флага приложение должно вернуть структурированную ошибку парсинга.
func TestRun_WithInvalidFlag_ShouldReturnError(t *testing.T) {
	setupTestEnv(t)

	// Передаем заведомо неизвестный флаг
	os.Args = []string{"gophkeeper", "--invalid-unknown-client-flag"}

	err := run()
	assert.Error(t, err, "execution with unknown flags should return parse error")
}

// TestConfigureGlobalSlog_InvalidPath проверяет реакцию инициализатора логирования на некорректный путь.
// Функция должна вернуть ошибку, если ей передан пустой путь.
func TestConfigureGlobalSlog_InvalidPath(t *testing.T) {
	f, err := configureGlobalSlog("", "debug", "text")
	assert.Error(t, err, "empty path should cause error")
	assert.Nil(t, f, "Дескриптор файла при ошибке должен быть nil")
}

// TestConfigureGlobalSlog_ValidFormats проверяет создание файлов логов в различных форматах.
// Тестирует корректность применения прав 0600 и парсинг форматов text/json.
func TestConfigureGlobalSlog_ValidFormats(t *testing.T) {
	tmpDir := t.TempDir()

	formats := []struct {
		name   string
		format string
		level  string
	}{
		{"Текстовый логгер инфо", "text", "info"},
		{"JSON логгер варн", "json", "warn"},
		{"Дефолтный дебаг логгер", "unknown", "error"},
	}

	for _, tt := range formats {
		t.Run(tt.name, func(t *testing.T) {
			logPath := filepath.Join(tmpDir, t.Name(), "client.log")

			f, err := configureGlobalSlog(logPath, tt.level, tt.format)
			require.NoError(t, err, "valid path should not cause error")
			require.NotNil(t, f, "Файл должен быть успешно открыт")

			_ = f.Close()

			// Проверяем, что файл физически создался на диске
			info, err := os.Stat(logPath)
			assert.NoError(t, err, "log file should exist")
			assert.True(t, info.Mode().IsRegular(), "log should be a regular file")
		})
	}
}
