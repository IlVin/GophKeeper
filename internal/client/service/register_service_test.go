package service_test

import (
	"context"
	"testing"

	"gophkeeper/internal/client/service"

	"github.com/stretchr/testify/assert"
)

// TestRegisterService_ConstructorПроверяет базовую сборку фабрики сервиса регистрации.
func TestRegisterService_Constructor(t *testing.T) {
	store := &mockDeviceStore{}

	// Конструируем сервис с nil сетевыми зависимостями чисто под проверку контракта сборки
	regServ := service.NewRegisterService(store, nil, nil, nil)

	assert.NotNil(t, regServ, "Конструктор сервиса регистрации обязан успешно собирать объект")
}

// TestRunRegistration_AbortsIfEnvironmentMissing проверяет срабатывание защитного ИБ-барьера,
// если пользователь пытается зарегистрировать неинициализированный локально контейнер.
func TestRunRegistration_AbortsIfEnvironmentMissing(t *testing.T) {
	store := &mockDeviceStore{savedState: nil} // Пустая база данных
	regServ := service.NewRegisterService(store, nil, nil, nil)
	ctx := context.Background()

	err := regServ.RunRegistration(ctx, "localhost:443")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "environment is not initialized", "Метод должен упасть с понятной ошибкой до gRPC вызовов")
}
