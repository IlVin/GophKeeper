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
