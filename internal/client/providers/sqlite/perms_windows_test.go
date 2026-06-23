//go:build windows

package sqlite_test

import (
	"os"
	"path/filepath"
	"testing"

	"gophkeeper/internal/client/providers/sqlite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateFilePermissions_Windows_Success проверяет успешное прохождение
// ACL-валидации на файле, созданном текущим пользователем в его временной директории.
func TestValidateFilePermissions_Windows_Success(t *testing.T) {
	tmpDir := t.TempDir()
	dbFile := filepath.Join(tmpDir, "windows_vault.db")

	err := os.WriteFile(dbFile, []byte("sqlite-data-bytes"), 0o600)
	require.NoError(t, err)

	info, err := os.Stat(dbFile)
	require.NoError(t, err)

	// На платформе Windows созданный файл наследует права текущего юзера, тест обязан пройти
	err = sqlite.ValidateFilePermissions(dbFile, info)
	assert.NoError(t, err, "Файл, созданный текущим пользователем, должен успешно проходить ACL-контроль")
}

// TestValidateDirPermissions_Windows_Success проверяет ACL-валидацию для папки.
func TestValidateDirPermissions_Windows_Success(t *testing.T) {
	tmpDir := t.TempDir()

	info, err := os.Stat(tmpDir)
	require.NoError(t, err)

	err = sqlite.ValidateDirPermissions(tmpDir, info)
	assert.NoError(t, err, "Временная папка пользователя должна отвечать критериям безопасности ACL")
}
