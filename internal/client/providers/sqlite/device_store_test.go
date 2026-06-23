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
		CreatedAt:                time.Now().UTC().Format(time.RFC3339),
	}

	// Сохраняем состояние
	err := store.SaveDeviceState(ctx, mockState)
	require.NoError(t, err, "Сохранение валидного состояния не должно возвращать ошибок")

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
		CreatedAt:                time.Now().UTC().Format(time.RFC3339),
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
		},
	}

	// Запускаем транзакцию Reconcile
	err = store.ExecuteReconcileTransaction(ctx, stateNew, mockRecords)
	require.NoError(t, err, "Транзакция согласования должна выполниться успешно на верных плейсхолдерах")

	// Проверяем, что синглтон-состояние обновилось
	checkState, err := store.ReadDeviceState(ctx)
	require.NoError(t, err)
	assert.Equal(t, "new-canonical-server-user-id", *checkState.UserID)
}
