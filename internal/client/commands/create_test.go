package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseMetadata_WithValidJSON_ShouldSuccess проверяет корректный парсинг метаданных.
func TestParseMetadata_WithValidJSON_ShouldSuccess(t *testing.T) {
	meta, err := parseMetadata(`{"owner":"admin","env":"prod"}`)
	require.NoError(t, err)
	assert.Equal(t, "admin", meta["owner"])
	assert.Equal(t, "prod", meta["env"])
}

// TestParseMetadata_WithInvalidJSON_ShouldReturnError проверяет генерацию ошибки при ломаном синтаксисе.
func TestParseMetadata_WithInvalidJSON_ShouldReturnError(t *testing.T) {
	meta, err := parseMetadata(`{"broken": json`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "неверный формат --meta")
	assert.Nil(t, meta)
}

// TestResolvePayload_WithTextType_ShouldReturnBytes проверяет извлечение текстовой нагрузки.
func TestResolvePayload_WithTextType_ShouldReturnBytes(t *testing.T) {
	bytes, err := resolvePayload("text", "mysecretpassword", "")
	require.NoError(t, err)
	assert.Equal(t, []byte("mysecretpassword"), bytes)
}

// TestResolvePayload_WithTextTypeEmptyPayload_ShouldReturnError проверяет барьер на пустую строку.
func TestResolvePayload_WithTextTypeEmptyPayload_ShouldReturnError(t *testing.T) {
	bytes, err := resolvePayload("credentials", "   ", "")
	assert.Error(t, err)
	assert.Nil(t, bytes)
}

// TestResolvePayload_WithBinaryTypeExceedingLimit_ShouldReturnError проверяет барьер
// ИБ-безопасности RAM на размер загружаемого бинарного файла.
func TestResolvePayload_WithBinaryTypeExceedingLimit_ShouldReturnError(t *testing.T) {
	tmpDir := t.TempDir()
	hugeFile := filepath.Join(tmpDir, "huge.bin")

	// Симулируем файл размером больше 10 МБ (10 МБ + 1 байт)
	f, err := os.OpenFile(hugeFile, os.O_RDWR|os.O_CREATE, 0o600)
	require.NoError(t, err)
	err = f.Truncate(maxBinarySize + 1)
	require.NoError(t, err)
	_ = f.Close()

	bytes, err := resolvePayload("binary", "", hugeFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "размер файла превышает лимит безопасности")
	assert.Nil(t, bytes)
}
