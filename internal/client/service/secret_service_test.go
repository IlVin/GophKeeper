package service_test

import (
	"context"
	"testing"
	"time"

	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/client/service"

	"github.com/stretchr/testify/assert"
)

// mockSecretStore реализует интерфейс SecretStore в RAM для фикстур
type mockSecretStore struct {
	savedRecord *repository.EncryptedRecord
}

func (m *mockSecretStore) Save(ctx context.Context, record *repository.EncryptedRecord) error {
	m.savedRecord = record
	return nil
}

func (m *mockSecretStore) GetByID(ctx context.Context, id string) (*repository.EncryptedRecord, error) {
	if m.savedRecord != nil && m.savedRecord.ID == id {
		return m.savedRecord, nil
	}
	return nil, nil
}

func (m *mockSecretStore) GetByName(ctx context.Context, name string) (*repository.EncryptedRecord, error) {
	if m.savedRecord != nil && m.savedRecord.Name == name {
		return m.savedRecord, nil
	}
	return nil, nil
}

func (m *mockSecretStore) List(ctx context.Context) ([]repository.RecordMetadata, error) {
	if m.savedRecord == nil {
		return nil, nil
	}
	return []repository.RecordMetadata{{ID: m.savedRecord.ID, Name: m.savedRecord.Name, Type: m.savedRecord.Type, UpdatedAt: time.Now()}}, nil
}

func (m *mockSecretStore) Delete(ctx context.Context, id string) error {
	m.savedRecord = nil
	return nil
}

func (m *mockSecretStore) GetSyncMetadata(ctx context.Context) (map[string]time.Time, error) {
	return nil, nil
}

func (m *mockSecretStore) SaveRaw(ctx context.Context, r *repository.EncryptedRecord) error {
	m.savedRecord = r
	return nil
}

func (m *mockSecretStore) GetRawByID(ctx context.Context, id string) (*repository.EncryptedRecord, error) {
	return m.savedRecord, nil
}

// TestSecretService_CreateSecret_FailsIfEmptyPayload проверяет fail-fast барьер
// на попытку запечатать пустую полезную нагрузку.
func TestSecretService_CreateSecret_FailsIfEmptyPayload(t *testing.T) {
	secStore := &mockSecretStore{}
	devStore := &mockDeviceStore{savedState: nil}

	serv := service.NewSecretService(secStore, devStore, nil)
	ctx := context.Background()

	err := serv.CreateSecret(ctx, "google-pass", "credentials", []byte(""))
	assert.Error(t, err, "Метод должен вернуть ошибку при пустом plaintextPayload")
	assert.Contains(t, err.Error(), "secret payload cannot be empty")
}

// TestSecretService_UnsealSecret_FailsIfEnvironmentMissing проверяет fail-fast барьер,
// если пользователь пытается прочитать секрет в неинициализированном контейнере.
func TestSecretService_UnsealSecret_FailsIfEnvironmentMissing(t *testing.T) {
	secStore := &mockSecretStore{}
	devStore := &mockDeviceStore{savedState: nil} // Имитируем пустую базу данных

	serv := service.NewSecretService(secStore, devStore, nil)
	ctx := context.Background()

	name, plain, err := serv.UnsealSecret(ctx, "some-id", true)
	assert.Error(t, err)
	assert.Empty(t, name)
	assert.Nil(t, plain)
	assert.Contains(t, err.Error(), "environment is not initialized")
}
