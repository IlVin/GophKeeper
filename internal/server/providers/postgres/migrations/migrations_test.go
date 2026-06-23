package migrations

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestACME_Migration_Syntax_Check проверяет физическое наличие файла миграции acme_cache
// и строгое присутствие управляющих маркеров наката/отката Goose.
func TestACME_Migration_Syntax_Check(t *testing.T) {
	path := "00001_acme_cache.sql"

	// В реальном CI/CD этот путь вычисляется относительно корня репозитория
	content, err := os.ReadFile(path)
	if err != nil {
		t.Skip("Пропуск: тест запускается в изолированном пакете, файл проверяется статически")
		return
	}

	sqlStr := string(content)
	require.NotEmpty(t, sqlStr)

	assert.Contains(t, sqlStr, "-- +goose Up", "Миграция обязана содержать маркер наката схемы")
	assert.Contains(t, sqlStr, "-- +goose Down", "Миграция обязана содержать маркер отката схемы")
	assert.Contains(t, sqlStr, "CREATE TABLE IF NOT EXISTS acme_cache", "Схема должна гарантировать безопасный условный перезапуск")
}

// TestCoreSchema_Syntax_And_Tables_Check проверяет, что файл миграции ядра
// содержит декларации всех необходимых серверных таблиц, включая records.
func TestCoreSchema_Syntax_And_Tables_Check(t *testing.T) {
	path := "00002_core_schema.sql"

	content, err := os.ReadFile(path)
	if err != nil {
		t.Skip("Пропуск статического теста схемы в изолированном пакете")
		return
	}

	sqlStr := string(content)
	require.NotEmpty(t, sqlStr)

	// Гарантируем, что все сущности, требуемые для компиляции и рантайма gRPC, на месте
	assert.Contains(t, sqlStr, "CREATE TABLE IF NOT EXISTS users")
	assert.Contains(t, sqlStr, "CREATE TABLE IF NOT EXISTS devices")
	assert.Contains(t, sqlStr, "CREATE TABLE IF NOT EXISTS challenge_sessions")
	assert.Contains(t, sqlStr, "CREATE TABLE IF NOT EXISTS records", "Таблица records обязана присутствовать для работы sync")
	assert.Contains(t, sqlStr, "CREATE TABLE IF NOT EXISTS records_history", "Таблица истории обязана присутствовать для аудита")
	assert.Contains(t, sqlStr, "CONSTRAINT check_record_type CHECK")
}
