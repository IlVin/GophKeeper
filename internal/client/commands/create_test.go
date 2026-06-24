package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseMetadata_WithValidJSON_ShouldSuccess checks correct metadata parsing.
func TestParseMetadata_WithValidJSON_ShouldSuccess(t *testing.T) {
	meta, err := parseMetadata(`{"owner":"admin","env":"prod"}`)
	require.NoError(t, err)
	assert.Equal(t, "admin", meta["owner"])
	assert.Equal(t, "prod", meta["env"])
}

// TestParseMetadata_WithInvalidJSON_ShouldReturnError checks error generation on broken syntax.
func TestParseMetadata_WithInvalidJSON_ShouldReturnError(t *testing.T) {
	meta, err := parseMetadata(`{"broken": json`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --meta format")
	assert.Nil(t, meta)
}

// TestResolvePayload_WithTextType_ShouldReturnBytes checks text payload extraction.
func TestResolvePayload_WithTextType_ShouldReturnBytes(t *testing.T) {
	bytes, err := resolvePayload("text", "mysecretpassword", "")
	require.NoError(t, err)
	assert.Equal(t, []byte("mysecretpassword"), bytes)
}

// TestResolvePayload_WithTextTypeEmptyPayload_ShouldReturnError checks empty string barrier.
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

	// Simulate file larger than 10 MB (10 MB + 1 byte)
	f, err := os.OpenFile(hugeFile, os.O_RDWR|os.O_CREATE, 0o600)
	require.NoError(t, err)
	err = f.Truncate(maxBinarySize + 1)
	require.NoError(t, err)
	_ = f.Close()

	bytes, err := resolvePayload("binary", "", hugeFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "file size exceeds security limit")
	assert.Nil(t, bytes)
}
