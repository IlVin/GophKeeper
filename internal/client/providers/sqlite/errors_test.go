package sqlite_test

import (
	"os"
	"path/filepath"
	"testing"

	"gophkeeper/internal/client/providers/sqlite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileSystemErrors_Messages проверяет строгое соответствие англоязычных
// текстов каноничных ошибок ИБ-инвариантам СУБД.
func TestFileSystemErrors_Messages(t *testing.T) {
	assert.Equal(t, "sqlite path is empty", sqlite.ErrEmptyPath.Error())
	assert.Equal(t, "parent path is not a directory", sqlite.ErrParentDirNotDirectory.Error())
	assert.Equal(t, "parent directory has insecure permissions", sqlite.ErrParentDirInsecurePermissions.Error())
	assert.Equal(t, "database path is not a regular file", sqlite.ErrDatabaseFileNotRegular.Error())
	assert.Equal(t, "database file has insecure permissions", sqlite.ErrDatabaseFileInsecurePermissions.Error())
}

// TestLogFileSystemIncident_ShouldNotPanic проверяет устойчивость регистратора инцидентов
// ИБ к передаче различных параметров и гарантирует отсутствие паник в рантайме.
func TestLogFileSystemIncident_ShouldNotPanic(t *testing.T) {
	tmpDir := t.TempDir()
	dummyFile := filepath.Join(tmpDir, "incident_trigger.txt")

	// 1. Тест с валидным os.FileInfo
	err := os.WriteFile(dummyFile, []byte("test"), 0o644) // Намеренно небезопасные права
	require.NoError(t, err)

	info, err := os.Stat(dummyFile)
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		sqlite.LogFileSystemIncident("file validation check failed", dummyFile, info)
	}, "Incident logging method must not panic with valid parameters")

	// 2. Тест-барьер с nil pointer info protection
	assert.NotPanics(t, func() {
		sqlite.LogFileSystemIncident("directory scan boundary layout failed", dummyFile, nil)
	}, "Incident logging method must safely handle nil FileInfo pointers")
}
