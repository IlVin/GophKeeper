package service_test

import (
	"context"
	"testing"

	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/client/service"

	"github.com/stretchr/testify/assert"
)

func (m *mockDeviceStore) GetAllRecords(ctx context.Context) ([]repository.EncryptedRecord, error) {
	return nil, nil
}

func (m *mockDeviceStore) ExecuteReconcileTransaction(ctx context.Context, state *repository.LocalDeviceState, records []repository.EncryptedRecord) error {
	m.savedState = state
	return nil
}

// TestReconcile_AbortsIfReadFails проверяет, что метод корректно прерывается
// с возвратом ошибки, если чтение состояния СУБД заблокировано или завершилось сбоем.
func TestReconcile_AbortsIfReadFails(t *testing.T) {
	// Передаем пустое хранилище, которое честно вернет ошибку "no rows"
	initServ := service.NewInitService(&mockDeviceStore{savedState: nil}, nil)
	ctx := context.Background()

	err := initServ.ReconcileContainer(ctx, nil, nil, nil, nil, "", nil)

	assert.Error(t, err, "Метод обязан вернуть ошибку, если база данных вернула сбой чтения")
	assert.Contains(t, err.Error(), "read current state for reconcile", "Контекст ошибки должен указывать на сбой чтения")
}
