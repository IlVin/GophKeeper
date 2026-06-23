//go:build unix

package sqlite_test

import (
	"os"
	"path/filepath"
	"testing"

	"gophkeeper/internal/client/providers/sqlite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateDirPermissions_WithInsecureMask_ShouldReturnError проверяет реакцию
// валидатора на небезопасную маску папки (например, 0755 вместо 0700).
func TestValidateDirPermissions_WithInsecureMask_ShouldReturnError(t *testing.T) {
	tmpDir := t.TempDir()

	// Намеренно выставляем небезопасные права доступа 0755
	err := os.Chmod(tmpDir, 0o755)
	require.NoError(t, err)

	info, err := os.Stat(tmpDir)
	require.NoError(t, err)

	err = sqlite.ValidateDirPermissions(tmpDir, info)
	assert.ErrorIs(t, err, sqlite.ErrParentDirInsecurePermissions,
		"Валидатор должен вернуть ошибку ErrParentDirInsecurePermissions при маске 0755")
	assert.Contains(t, err.Error(), "expected 0700", "Сообщение должно содержать ожидаемую маску на английском языке")
}

// TestValidateDirPermissions_WithValidMask_ShouldSuccess проверяет прохождение барьера при правах 0700.
func TestValidateDirPermissions_WithValidMask_ShouldSuccess(t *testing.T) {
	tmpDir := t.TempDir()

	err := os.Chmod(tmpDir, 0o700)
	require.NoError(t, err)

	info, err := os.Stat(tmpDir)
	require.NoError(t, err)

	err = sqlite.ValidateDirPermissions(tmpDir, info)
	assert.NoError(t, err, "При корректных правах 0700 ошибка возвращаться не должна")
}

// TestValidateFilePermissions_WithInsecureMask_ShouldReturnError проверяет реакцию
// валидатора на избыточные права файла контейнера (например, 0644 вместо 0600).
func TestValidateFilePermissions_WithInsecureMask_ShouldReturnError(t *testing.T) {
	tmpDir := t.TempDir()

	// Папку инитим валидно, чтобы дойти до файла
	err := os.Chmod(tmpDir, 0o700)
	require.NoError(t, err)

	dbFile := filepath.Join(tmpDir, "vault.db")
	err = os.WriteFile(dbFile, []byte("sqlite-head"), 0o644) // Избыточные права 0644
	require.NoError(t, err)

	info, err := os.Stat(dbFile)
	require.NoError(t, err)

	err = sqlite.ValidateFilePermissions(dbFile, info)
	assert.ErrorIs(t, err, sqlite.ErrDatabaseFileInsecurePermissions,
		"Валидатор должен заблокировать файл с маской 0644")
	assert.Contains(t, err.Error(), "expected 0600")
}

// TestValidateFilePermissions_WithValidMask_ShouldSuccess проверяет успешный проход при 0600.
func TestValidateFilePermissions_WithValidMask_ShouldSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	err := os.Chmod(tmpDir, 0o700)
	require.NoError(t, err)

	dbFile := filepath.Join(tmpDir, "vault.db")
	err = os.WriteFile(dbFile, []byte("sqlite-head"), 0o600) // Строгие права 0600
	require.NoError(t, err)

	info, err := os.Stat(dbFile)
	require.NoError(t, err)

	err = sqlite.ValidateFilePermissions(dbFile, info)
	assert.NoError(t, err, "При корректных правах 0600 файл должен успешно пройти проверку")
}
