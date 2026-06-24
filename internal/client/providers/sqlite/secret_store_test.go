package sqlite_test

import (
	"context"
	"testing"
	"time"

	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// TestSecretStore_SaveAndGet_Success проверяет штатный цикл сохранения, поиска по ID и по имени.
func TestSecretStore_SaveAndGet_Success(t *testing.T) {
	db := setupMockDB(t)
	defer db.Close()

	store := sqlite.NewSQLiteSecretStore(db)
	ctx := context.Background()

	user := "user-uuid-canonical"
	mockRecord := &repository.EncryptedRecord{
		ID:        "22222222-3333-4444-5555-666666666666",
		UserID:    &user,
		Name:      "google-auth-token",
		Type:      "credentials",
		Envelope:  []byte("crypto-bytes-envelope-poly1305"),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
	}

	// Тест Save (Insert)
	err := store.Save(ctx, mockRecord)
	require.NoError(t, err, "Сохранение записи на исправленных плейсхолдерах должно проходить без ошибок")

	// Тест GetByID
	fetchedByID, err := store.GetByID(ctx, mockRecord.ID)
	require.NoError(t, err)
	require.NotNil(t, fetchedByID)
	assert.Equal(t, mockRecord.Name, fetchedByID.Name)
	assert.Equal(t, mockRecord.Envelope, fetchedByID.Envelope)
	assert.True(t, mockRecord.CreatedAt.Equal(fetchedByID.CreatedAt), "Временные метки создания должны совпадать до секунды")

	// Тест GetByName
	fetchedByName, err := store.GetByName(ctx, mockRecord.Name)
	require.NoError(t, err)
	require.NotNil(t, fetchedByName)
	assert.Equal(t, mockRecord.ID, fetchedByName.ID)
}

// TestSecretStore_SaveRaw_LWW_Enforcement проверяет работу распределенной
// LWW-логики репликации при конфликтах версий.
func TestSecretStore_SaveRaw_LWW_Enforcement(t *testing.T) {
	db := setupMockDB(t)
	defer db.Close()

	store := sqlite.NewSQLiteSecretStore(db)
	ctx := context.Background()

	baseTime := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	recordID := "55555555-5555-5555-5555-555555555555"

	// 1. Записываем базовую локальную запись
	baseRec := &repository.EncryptedRecord{
		ID:        recordID,
		Name:      "sync-record",
		Type:      "text",
		Envelope:  []byte("local-version-payload"),
		CreatedAt: baseTime,
		UpdatedAt: baseTime,
	}
	err := store.Save(ctx, baseRec)
	require.NoError(t, err)

	// 2. Сценарий А: С сервера пришел пакет, который СТАРШЕ локального (LWW должен ОТКЛОНИТЬ)
	olderServerRec := &repository.EncryptedRecord{
		ID:        recordID,
		Name:      "sync-record",
		Type:      "text",
		Envelope:  []byte("older-server-payload"),
		CreatedAt: baseTime,
		UpdatedAt: baseTime.Add(-10 * time.Minute), // На 10 минут старше
	}
	err = store.SaveRaw(ctx, olderServerRec)
	require.NoError(t, err)

	// Верифицируем, что данные в базе НЕ изменились (LWW защитил локальную копию)
	checkRec, err := store.GetByID(ctx, recordID)
	require.NoError(t, err)
	assert.Equal(t, []byte("local-version-payload"), checkRec.Envelope, "LWW обязан отклонить устаревший сетевой пакет")

	// 3. Сценарий Б: С сервера пришел пакет, который СВЕЖЕЕ локального (LWW должен ОБНОВИТЬ)
	newerServerRec := &repository.EncryptedRecord{
		ID:        recordID,
		Name:      "sync-record",
		Type:      "text",
		Envelope:  []byte("fresh-server-payload"),
		CreatedAt: baseTime,
		UpdatedAt: baseTime.Add(10 * time.Minute), // На 10 минут свежее
	}
	err = store.SaveRaw(ctx, newerServerRec)
	require.NoError(t, err)

	// Верифицируем, что данные обновились серверными значениями
	checkRecUpdated, err := store.GetByID(ctx, recordID)
	require.NoError(t, err)
	assert.Equal(t, []byte("fresh-server-payload"), checkRecUpdated.Envelope, "LWW обязан применить свежий сетевой пакет")
}

// TestSecretStore_SoftDelete проверяет мягкое удаление и фильтрацию записей.
func TestSecretStore_SoftDelete(t *testing.T) {
	db := setupMockDB(t)
	defer db.Close()

	store := sqlite.NewSQLiteSecretStore(db)
	ctx := context.Background()

	user := "test-user-soft-delete"

	// 1. Создаем запись
	record := &repository.EncryptedRecord{
		ID:        "11111111-2222-3333-4444-555555555555",
		UserID:    &user,
		Name:      "soft-delete-test",
		Type:      "text",
		Envelope:  []byte("test-envelope"),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
		IsDeleted: 0,
	}

	err := store.Save(ctx, record)
	require.NoError(t, err)

	// 2. Проверяем, что запись доступна
	fetched, err := store.GetByID(ctx, record.ID)
	require.NoError(t, err)
	require.NotNil(t, fetched)
	assert.Equal(t, int32(0), fetched.IsDeleted)

	// 3. Мягко удаляем запись
	err = store.Delete(ctx, record.ID)
	require.NoError(t, err)

	// 4. Проверяем, что запись НЕ доступна через GetByID (фильтр is_deleted=0)
	deletedByID, err := store.GetByID(ctx, record.ID)
	require.NoError(t, err)
	assert.Nil(t, deletedByID, "Удаленная запись не должна возвращаться через GetByID")

	// 5. Проверяем, что запись НЕ доступна через GetByName (фильтр is_deleted=0)
	deletedByName, err := store.GetByName(ctx, record.Name)
	require.NoError(t, err)
	assert.Nil(t, deletedByName, "Удаленная запись не должна возвращаться через GetByName")

	// 6. Проверяем, что запись НЕ отображается в List (фильтр is_deleted=0)
	list, err := store.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, list, "Удаленная запись не должна отображаться в List")

	// 7. Проверяем, что запись ДОСТУПНА через GetRawByID (без фильтра)
	rawRecord, err := store.GetRawByID(ctx, record.ID)
	require.NoError(t, err)
	require.NotNil(t, rawRecord)
	assert.Equal(t, int32(1), rawRecord.IsDeleted, "GetRawByID должен возвращать is_deleted=1")
	assert.Equal(t, record.ID, rawRecord.ID)
	assert.Equal(t, record.Name, rawRecord.Name)

	// 8. Проверяем, что запись присутствует в SyncMetadata (для синхронизации)
	syncMeta, err := store.GetSyncMetadata(ctx)
	require.NoError(t, err)
	assert.Contains(t, syncMeta, record.ID, "Удаленная запись должна присутствовать в SyncMetadata")
}

// TestSecretStore_SoftDelete_Restore проверяет восстановление мягко удаленной записи.
func TestSecretStore_SoftDelete_Restore(t *testing.T) {
	db := setupMockDB(t)
	defer db.Close()

	store := sqlite.NewSQLiteSecretStore(db)
	ctx := context.Background()

	user := "test-user-restore"
	recordID := "22222222-3333-4444-5555-666666666666"

	// 1. Создаем запись
	record := &repository.EncryptedRecord{
		ID:        recordID,
		UserID:    &user,
		Name:      "restore-test",
		Type:      "text",
		Envelope:  []byte("initial-envelope"),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
		IsDeleted: 0,
	}

	err := store.Save(ctx, record)
	require.NoError(t, err)

	// 2. Мягко удаляем запись
	err = store.Delete(ctx, recordID)
	require.NoError(t, err)

	// 3. Восстанавливаем запись (сохраняем с is_deleted=0)
	restoredRecord := &repository.EncryptedRecord{
		ID:        recordID,
		UserID:    &user,
		Name:      "restore-test",
		Type:      "text",
		Envelope:  []byte("restored-envelope"),
		CreatedAt: record.CreatedAt, // Сохраняем оригинальную дату создания
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
		IsDeleted: 0, // Восстанавливаем
	}

	err = store.Save(ctx, restoredRecord)
	require.NoError(t, err)

	// 4. Проверяем, что запись снова доступна
	fetched, err := store.GetByID(ctx, recordID)
	require.NoError(t, err)
	require.NotNil(t, fetched)
	assert.Equal(t, int32(0), fetched.IsDeleted, "Запись должна быть восстановлена (is_deleted=0)")
	assert.Equal(t, []byte("restored-envelope"), fetched.Envelope, "Данные должны обновиться")

	// 5. Проверяем, что запись отображается в List
	list, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 1, "Восстановленная запись должна отображаться в List")
	assert.Equal(t, recordID, list[0].ID)
}

// TestSecretStore_Save_PreservesIsDeleted проверяет, что Save сохраняет is_deleted как есть.
func TestSecretStore_Save_PreservesIsDeleted(t *testing.T) {
	db := setupMockDB(t)
	defer db.Close()

	store := sqlite.NewSQLiteSecretStore(db)
	ctx := context.Background()

	user := "test-user-preserve"
	recordID := "33333333-4444-5555-6666-777777777777"

	// 1. Создаем запись с is_deleted=0
	record := &repository.EncryptedRecord{
		ID:        recordID,
		UserID:    &user,
		Name:      "preserve-test",
		Type:      "text",
		Envelope:  []byte("test-envelope"),
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
		IsDeleted: 0,
	}

	err := store.Save(ctx, record)
	require.NoError(t, err)

	// 2. Обновляем запись с is_deleted=1 (эмулируем ситуацию, когда кто-то передал удаленную запись)
	updatedRecord := &repository.EncryptedRecord{
		ID:        recordID,
		UserID:    &user,
		Name:      "preserve-test",
		Type:      "text",
		Envelope:  []byte("updated-envelope"),
		CreatedAt: record.CreatedAt,
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
		IsDeleted: 1, // Пытаемся сохранить как удаленную
	}

	err = store.Save(ctx, updatedRecord)
	require.NoError(t, err)

	// 3. Проверяем, что is_deleted сохранился как 1
	rawRecord, err := store.GetRawByID(ctx, recordID)
	require.NoError(t, err)
	require.NotNil(t, rawRecord)
	assert.Equal(t, int32(1), rawRecord.IsDeleted, "Save должен сохранять is_deleted как есть")
	assert.Equal(t, []byte("updated-envelope"), rawRecord.Envelope, "Данные должны обновиться")

	// 4. Проверяем, что через обычный GetByID запись не видна
	fetched, err := store.GetByID(ctx, recordID)
	require.NoError(t, err)
	assert.Nil(t, fetched, "Запись с is_deleted=1 не должна возвращаться через GetByID")
}
