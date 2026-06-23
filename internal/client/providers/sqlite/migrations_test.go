package sqlite_test

import (
	"database/sql"
	"testing"

	"gophkeeper/internal/client/providers/sqlite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// TestMigration_00001_Init_ShouldSuccess проверяет синтаксическую корректность
// SQL-кода миграции и успешное создание структуры таблиц в пустой базе данных.
func TestMigration_00001_Init_ShouldSuccess(t *testing.T) {
	// Открываем чистую изолированную базу данных прямо в оперативной памяти (In-Memory)
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer func() {
		_ = db.Close()
	}()

	// Проверяем, что таблицы device_state еще не существует
	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='device_state';").Scan(&tableName)
	assert.ErrorIs(t, err, sql.ErrNoRows, "Изначально таблица должна отсутствовать")

	// Накатываем миграции через наш системный метод Migrate пакета sqlite
	// (Внутри он автоматически подтянет эмбед-файлы через go:embed migrations/*.sql)
	err = sqlite.Migrate(db)
	require.NoError(t, err, "Накат SQL миграций goose должен завершиться без синтаксических ошибок")

	// Верифицируем, что таблица успешно создалась на диске/в памяти
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='device_state';").Scan(&tableName)
	require.NoError(t, err)
	assert.Equal(t, "device_state", tableName, "Таблица device_state должна физически существовать в схеме")

	// Проверяем, что служебная таблица goose_db_version зафиксировала версию 1
	var currentVersion int64
	err = db.QueryRow("SELECT version_id FROM goose_db_version ORDER BY id DESC LIMIT 1;").Scan(&currentVersion)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, currentVersion, int64(1), "Версия схемы СУБД должна быть не меньше 1")
}

// TestMigrations_FullChain_ShouldEnforceConstraints проверяет сквозной накат всей цепочки
// SQL-миграций и верифицирует работу каскадов FOREIGN KEY и CHECK-инвариантов.
func TestMigrations_FullChain_ShouldEnforceConstraints(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	// 1. Накатываем всю схему
	err = sqlite.Migrate(db)
	require.NoError(t, err, "Накат полной схемы Goose должен завершиться успешно")

	// Включаем принудительную поддержку Foreign Keys для текущей сессии тестирования
	_, err = db.Exec("PRAGMA foreign_keys = ON;")
	require.NoError(t, err)

	// 2. Имитируем заполнение device_state для прохождения foreign key барьера.
	// Передаем честные 32 байта для account_salt (64 символа в hex-строке)
	_, err = db.Exec(`
		INSERT INTO device_state (id, device_id, ssh_public_key, account_salt, device_master_key_envelope, account_bootstrap_envelope, user_id)
		VALUES (1, 'a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d', x'0102', x'0102030405060708010203040506070801020304050607080102030405060708', x'05', x'06', 'user-canonical-id');
	`)
	require.NoError(t, err)

	// 3. ТЕСТ ИНВАРИАНТА CHECK: Попытка записать некорректный тип секрета должна быть заблокирована СУБД
	invalidQuery := `
		INSERT INTO records (id, user_id, name, type, envelope, created_at, updated_at)
		VALUES ('11111111-2222-3333-4444-555555555555', 'user-canonical-id', 'test-key', 'broken-type-value', x'09', '2026-06-23T00:00:00Z', '2026-06-23T00:00:00Z');
	`
	_, err = db.Exec(invalidQuery)
	assert.Error(t, err, "База данных обязана отклонить запись с невалидным полем type")
	assert.Contains(t, err.Error(), "CHECK constraint failed", "Причина отказа должна быть в CHECK-ограничении")

	// 4. ТЕСТ ВАЛИДНОЙ ЗАПИСИ: Корректные типы должны сохраняться беспрепятственно
	validQuery := `
		INSERT INTO records (id, user_id, name, type, envelope, created_at, updated_at)
		VALUES ('11111111-2222-3333-4444-555555555555', 'user-canonical-id', 'test-key', 'credentials', x'09', '2026-06-23T00:00:00Z', '2026-06-23T00:00:00Z');
	`
	_, err = db.Exec(validQuery)
	assert.NoError(t, err, "Валидная запись должна успешно сохраниться в СУБД")
}
