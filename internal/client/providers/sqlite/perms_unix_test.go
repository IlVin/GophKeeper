//go:build unix

package sqlite

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpen_RejectsInsecureExistingDirectoryPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")

	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	dbPath := filepath.Join(stateDir, "goph_keeper.db")

	_, err := Open(dbPath)
	if !errors.Is(err, ErrParentDirInsecurePermissions) {
		t.Fatalf("Open() error = %v, want %v", err, ErrParentDirInsecurePermissions)
	}
}

func TestOpen_RejectsInsecureExistingFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	dbPath := filepath.Join(stateDir, "goph_keeper.db")

	f, err := os.OpenFile(dbPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	_, err = Open(dbPath)
	if !errors.Is(err, ErrDatabaseFileInsecurePermissions) {
		t.Fatalf("Open() error = %v, want %v", err, ErrDatabaseFileInsecurePermissions)
	}
}

func TestValidatePermissions_UnixStrictBounds(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Тест безопасных прав директории (700)
	err := os.Chmod(tmpDir, 0700)
	require.NoError(t, err)
	info, err := os.Stat(tmpDir)
	require.NoError(t, err)

	err = ValidateDirPermissions(tmpDir, info)
	assert.NoError(t, err)

	// 2. Тест небезопасных прав директории (755)
	err = os.Chmod(tmpDir, 0755)
	require.NoError(t, err)
	info, err = os.Stat(tmpDir)
	require.NoError(t, err)

	err = ValidateDirPermissions(tmpDir, info)
	assert.ErrorIs(t, err, ErrParentDirInsecurePermissions)

	// 3. Тест безопасного файла БД (600)
	dbPath := filepath.Join(tmpDir, "test.db")
	err = os.WriteFile(dbPath, []byte("mock-db"), 0600)
	require.NoError(t, err)
	info, err = os.Stat(dbPath)
	require.NoError(t, err)

	err = ValidateFilePermissions(dbPath, info)
	assert.NoError(t, err)
}
