package app

import (
	"database/sql"
	"testing"

	"gophkeeper/internal/client/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewApp_WithValidParams_ShouldSuccess проверяет корректную сборку контейнера
// при передаче всех обязательных валидных зависимостей.
func TestNewApp_WithValidParams_ShouldSuccess(t *testing.T) {
	// Создаем фейковый инициализированный пул sql.DB
	fakeDB := &sql.DB{}

	// Конструируем подструктуры строго через фабричные функции пакета config
	appCfg := config.NewAppConfig("", "")
	storageCfg := config.NewStorageConfig("")
	loggingCfg := config.NewLoggingConfig("", "debug", "")

	fakeCfg := config.NewConfig(appCfg, storageCfg, loggingCfg)

	appContainer, err := NewApp(fakeCfg, fakeDB)

	require.NoError(t, err, "constructor should not return error with valid parameters")
	require.NotNil(t, appContainer, "application container should be created successfully")

	// Проверяем работу инкапсулированных геттеров
	assert.Equal(t, fakeDB, appContainer.DB(), "DB() getter should return the same pointer")
	assert.Equal(t, "debug", appContainer.Config().Logging().Level(), "Config() getter should return correct data structure")
}

// TestNewApp_WithNilDB_ShouldReturnError проверяет срабатывание барьера fail-fast
// валидации при попытке прокинуть пустую ссылку на пул СУБД.
func TestNewApp_WithNilDB_ShouldReturnError(t *testing.T) {
	// Конструируем пустую конфигурацию с соблюдением инкапсуляции через фабрики
	appCfg := config.NewAppConfig("", "")
	storageCfg := config.NewStorageConfig("")
	loggingCfg := config.NewLoggingConfig("", "", "")
	fakeCfg := config.NewConfig(appCfg, storageCfg, loggingCfg)

	appContainer, err := NewApp(fakeCfg, nil)

	assert.ErrorIs(t, err, ErrNilDatabase, "constructor should return specific ErrNilDatabase error")
	assert.Nil(t, appContainer, "on validation error application container should be nil")
}
