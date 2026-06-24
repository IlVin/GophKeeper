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
	records map[string]*repository.EncryptedRecord
	err     error
}

func (m *mockSecretStore) Save(ctx context.Context, record *repository.EncryptedRecord) error {
	if m.err != nil {
		return m.err
	}
	if m.records == nil {
		m.records = make(map[string]*repository.EncryptedRecord)
	}
	m.records[record.ID] = record
	return nil
}

func (m *mockSecretStore) GetByID(ctx context.Context, id string) (*repository.EncryptedRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.records == nil {
		return nil, nil
	}
	rec, ok := m.records[id]
	if !ok {
		return nil, nil
	}
	return rec, nil
}

func (m *mockSecretStore) GetByName(ctx context.Context, name string) (*repository.EncryptedRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.records == nil {
		return nil, nil
	}
	for _, rec := range m.records {
		if rec.Name == name {
			return rec, nil
		}
	}
	return nil, nil
}

func (m *mockSecretStore) List(ctx context.Context) ([]repository.RecordMetadata, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.records == nil {
		return nil, nil
	}
	var result []repository.RecordMetadata
	for _, rec := range m.records {
		result = append(result, repository.RecordMetadata{
			ID:        rec.ID,
			Name:      rec.Name,
			Type:      rec.Type,
			UpdatedAt: rec.UpdatedAt,
		})
	}
	return result, nil
}

func (m *mockSecretStore) Delete(ctx context.Context, id string) error {
	if m.err != nil {
		return m.err
	}
	if m.records != nil {
		delete(m.records, id)
	}
	return nil
}

func (m *mockSecretStore) GetSyncMetadata(ctx context.Context) (map[string]time.Time, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.records == nil {
		return nil, nil
	}
	result := make(map[string]time.Time)
	for id, rec := range m.records {
		result[id] = rec.UpdatedAt
	}
	return result, nil
}

func (m *mockSecretStore) SaveRaw(ctx context.Context, record *repository.EncryptedRecord) error {
	if m.err != nil {
		return m.err
	}
	if m.records == nil {
		m.records = make(map[string]*repository.EncryptedRecord)
	}
	m.records[record.ID] = record
	return nil
}

func (m *mockSecretStore) GetRawByID(ctx context.Context, id string) (*repository.EncryptedRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.records == nil {
		return nil, nil
	}
	rec, ok := m.records[id]
	if !ok {
		return nil, nil
	}
	return rec, nil
}

func (m *mockSecretStore) GetSyncMetadataWithDeleted(ctx context.Context) (map[string]repository.RecordVersionMeta, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.records == nil {
		return nil, nil
	}
	result := make(map[string]repository.RecordVersionMeta)
	for id, rec := range m.records {
		result[id] = repository.RecordVersionMeta{
			UpdatedAt: rec.UpdatedAt,
			IsDeleted: rec.IsDeleted,
		}
	}
	return result, nil
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
