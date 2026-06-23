package service_test

import (
	"context"
	"testing"

	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/client/service"

	"github.com/stretchr/testify/assert"
)

// mockDeviceStore реализует репозиторий DeviceStore чисто для сбора результатов вызова в RAM
type mockDeviceStore struct {
	savedState *repository.LocalDeviceState
}

func (m *mockDeviceStore) SaveDeviceState(ctx context.Context, state *repository.LocalDeviceState) error {
	m.savedState = state
	return nil
}

func (m *mockDeviceStore) ReadDeviceState(ctx context.Context) (*repository.LocalDeviceState, error) {
	return m.savedState, nil
}

// TestInitService_ConstructorПроверяет базовую сборку фабрики сервиса
func TestInitService_Constructor(t *testing.T) {
	store := &mockDeviceStore{}
	initServ := service.NewInitService(store, nil)

	assert.NotNil(t, initServ, "Конструктор сервиса инициализации должен успешно собирать объект")
}
