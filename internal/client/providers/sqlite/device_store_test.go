package sqlite_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// setupMockDB подготавливает in-memory базу данных с накаченной схемой миграций.
func setupMockDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)

	err = sqlite.Migrate(db)
	require.NoError(t, err)

	return db
}

// TestDeviceStore_SaveAndReadState_Success проверяет успешный цикл сохранения и чтения синглтона.
func TestDeviceStore_SaveAndReadState_Success(t *testing.T) {
	db := setupMockDB(t)
	defer db.Close()

	store := sqlite.NewSQLiteDeviceStore(db)
	ctx := context.Background()

	url := "https://gophkeeper.local"
	user := "user-uuid-1111"

	mockState := &repository.LocalDeviceState{
		ServerURL:                &url,
		UserID:                   &user,
		DeviceID:                 "33333333-4444-5555-6666-777777777777",
		SshPublicKey:             []byte("ssh-ed25519-mock-bytes"),
		AccountSalt:              make([]byte, 32),
		DeviceMasterKeyEnvelope:  []byte("device-envelope"),
		AccountBootstrapEnvelope: []byte("bootstrap-envelope"),
		CreatedAt:                time.Now().UTC().Format(time.RFC3339Nano),
	}

	// Сохраняем состояние
	err := store.SaveDeviceState(ctx, mockState)
	require.NoError(t, err, "Saving valid state should not return errors")

	// Читаем состояние обратно
	fetchedState, err := store.ReadDeviceState(ctx)
	require.NoError(t, err)
	require.NotNil(t, fetchedState)

	assert.Equal(t, *mockState.ServerURL, *fetchedState.ServerURL)
	assert.Equal(t, *mockState.UserID, *fetchedState.UserID)
	assert.Equal(t, mockState.DeviceID, fetchedState.DeviceID)
	assert.Equal(t, mockState.SshPublicKey, fetchedState.SshPublicKey)
}

// TestDeviceStore_ExecuteReconcileTransaction_Success проверяет атомарность
// и корректность каскадного обновления данных при миграции Reconcile.
func TestDeviceStore_ExecuteReconcileTransaction_Success(t *testing.T) {
	db := setupMockDB(t)
	defer db.Close()

	store := sqlite.NewSQLiteDeviceStore(db)
	ctx := context.Background()

	// 1. Сначала пишем базовое состояние
	userOld := "old-user"
	stateBase := &repository.LocalDeviceState{
		DeviceID:                 "33333333-4444-5555-6666-777777777777",
		UserID:                   &userOld,
		SshPublicKey:             []byte("pubkey"),
		AccountSalt:              make([]byte, 32),
		DeviceMasterKeyEnvelope:  []byte("env1"),
		AccountBootstrapEnvelope: []byte("env2"),
		CreatedAt:                time.Now().UTC().Format(time.RFC3339Nano),
	}
	err := store.SaveDeviceState(ctx, stateBase)
	require.NoError(t, err)

	// 2. Подготавливаем новые канонические структуры для Reconcile транзакции
	userNew := "new-canonical-server-user-id"
	stateNew := &repository.LocalDeviceState{
		DeviceID:                 "33333333-4444-5555-6666-777777777777",
		UserID:                   &userNew,
		SshPublicKey:             []byte("pubkey"),
		AccountSalt:              make([]byte, 32),
		DeviceMasterKeyEnvelope:  []byte("new-env1"),
		AccountBootstrapEnvelope: []byte("new-env2"),
		CreatedAt:                stateBase.CreatedAt,
	}

	mockRecords := []repository.EncryptedRecord{
		{
			ID:        "11111111-2222-3333-4444-555555555555",
			UserID:    &userNew,
			Name:      "yandex-mail",
			Type:      "credentials",
			Envelope:  []byte("encrypted-envelope-bytes"),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
			IsDeleted: 0,
		},
		{
			ID:        "22222222-3333-4444-5555-666666666666",
			UserID:    &userNew,
			Name:      "deleted-record",
			Type:      "text",
			Envelope:  []byte("deleted-envelope-bytes"),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
			IsDeleted: 1, // Удаленная запись
		},
	}

	// Запускаем транзакцию Reconcile
	err = store.ExecuteReconcileTransaction(ctx, stateNew, mockRecords)
	require.NoError(t, err, "Reconciliation transaction must succeed on correct placeholders")

	// Проверяем, что синглтон-состояние обновилось
	checkState, err := store.ReadDeviceState(ctx)
	require.NoError(t, err)
	assert.Equal(t, "new-canonical-server-user-id", *checkState.UserID)
}

// TestDeviceStore_ExecuteReconcileTransaction_PreservesIsDeleted проверяет,
// что Reconcile транзакция сохраняет is_deleted при миграции.
func TestDeviceStore_ExecuteReconcileTransaction_PreservesIsDeleted(t *testing.T) {
	db := setupMockDB(t)
	defer db.Close()

	store := sqlite.NewSQLiteDeviceStore(db)
	secretStore := sqlite.NewSQLiteSecretStore(db)
	ctx := context.Background()

	// 1. Создаем базовое состояние
	userOld := "old-user"
	stateBase := &repository.LocalDeviceState{
		DeviceID:                 "44444444-5555-6666-7777-888888888888",
		UserID:                   &userOld,
		SshPublicKey:             []byte("pubkey"),
		AccountSalt:              make([]byte, 32),
		DeviceMasterKeyEnvelope:  []byte("env1"),
		AccountBootstrapEnvelope: []byte("env2"),
		CreatedAt:                time.Now().UTC().Format(time.RFC3339Nano),
	}
	err := store.SaveDeviceState(ctx, stateBase)
	require.NoError(t, err)

	// 2. Создаем несколько записей с разными состояниями is_deleted
	records := []repository.EncryptedRecord{
		{
			ID:        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			UserID:    &userOld,
			Name:      "active-record",
			Type:      "text",
			Envelope:  []byte("active-envelope"),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
			IsDeleted: 0,
		},
		{
			ID:        "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
			UserID:    &userOld,
			Name:      "deleted-record",
			Type:      "text",
			Envelope:  []byte("deleted-envelope"),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
			IsDeleted: 1,
		},
	}

	for _, rec := range records {
		err = secretStore.Save(ctx, &rec)
		require.NoError(t, err)
	}

	// 3. Проверяем, что записи сохранились с правильным is_deleted
	rawActive, err := secretStore.GetRawByID(ctx, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	require.NoError(t, err)
	assert.Equal(t, int32(0), rawActive.IsDeleted)

	rawDeleted, err := secretStore.GetRawByID(ctx, "bbbbbbbb-cccc-dddd-eeee-ffffffffffff")
	require.NoError(t, err)
	assert.Equal(t, int32(1), rawDeleted.IsDeleted)

	// 4. Запускаем Reconcile транзакцию с новыми записями (миграция)
	userNew := "new-canonical-user"
	stateNew := &repository.LocalDeviceState{
		DeviceID:                 "44444444-5555-6666-7777-888888888888",
		UserID:                   &userNew,
		SshPublicKey:             []byte("pubkey"),
		AccountSalt:              make([]byte, 32),
		DeviceMasterKeyEnvelope:  []byte("new-env1"),
		AccountBootstrapEnvelope: []byte("new-env2"),
		CreatedAt:                stateBase.CreatedAt,
	}

	// Мигрируем записи с сохранением is_deleted
	migratedRecords := []repository.EncryptedRecord{
		{
			ID:        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			UserID:    &userNew,
			Name:      "active-record",
			Type:      "text",
			Envelope:  []byte("migrated-active-envelope"),
			CreatedAt: records[0].CreatedAt,
			UpdatedAt: time.Now().UTC(),
			IsDeleted: 0, // Сохраняем состояние
		},
		{
			ID:        "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
			UserID:    &userNew,
			Name:      "deleted-record",
			Type:      "text",
			Envelope:  []byte("migrated-deleted-envelope"),
			CreatedAt: records[1].CreatedAt,
			UpdatedAt: time.Now().UTC(),
			IsDeleted: 1, // Сохраняем состояние удаления
		},
	}

	err = store.ExecuteReconcileTransaction(ctx, stateNew, migratedRecords)
	require.NoError(t, err)

	// 5. Проверяем, что после миграции is_deleted сохранился
	rawActiveAfter, err := secretStore.GetRawByID(ctx, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	require.NoError(t, err)
	assert.Equal(t, int32(0), rawActiveAfter.IsDeleted, "Active record must remain active")
	assert.Equal(t, []byte("migrated-active-envelope"), rawActiveAfter.Envelope, "Data must update")

	rawDeletedAfter, err := secretStore.GetRawByID(ctx, "bbbbbbbb-cccc-dddd-eeee-ffffffffffff")
	require.NoError(t, err)
	assert.Equal(t, int32(1), rawDeletedAfter.IsDeleted, "Deleted record must remain deleted")
	assert.Equal(t, []byte("migrated-deleted-envelope"), rawDeletedAfter.Envelope, "Data must update")

	// 6. Проверяем, что через обычные методы удаленная запись не видна
	activeList, err := secretStore.List(ctx)
	require.NoError(t, err)
	assert.Len(t, activeList, 1, "List should contain only active record")
	assert.Equal(t, "active-record", activeList[0].Name)

	// 7. Проверяем, что удаленная запись не доступна через GetByID
	deletedByID, err := secretStore.GetByID(ctx, "bbbbbbbb-cccc-dddd-eeee-ffffffffffff")
	require.NoError(t, err)
	assert.Nil(t, deletedByID, "Deleted record must not be returned via GetByID")
}
