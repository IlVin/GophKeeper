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

	require.NoError(t, err, "Конструктор не должен возвращать ошибку при валидных параметрах")
	require.NotNil(t, appContainer, "Контейнер приложения должен быть успешно создан")

	// Проверяем работу инкапсулированных геттеров
	assert.Equal(t, fakeDB, appContainer.DB(), "Геттер DB() должен возвращать тот же указатель")
	assert.Equal(t, "debug", appContainer.Config().Logging().Level(), "Геттер Config() должен возвращать корректную структуру данных")
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

	assert.ErrorIs(t, err, ErrNilDatabase, "Конструктор должен вернуть специфичную ошибку ErrNilDatabase")
	assert.Nil(t, appContainer, "При ошибке валидации контейнер приложения должен быть nil")
}
