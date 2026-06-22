package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gophkeeper/internal/client/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew_WhenFileDoesNotExist_ShouldReturnDatabaseMissingError проверяет барьер
// инициализации, если пользователь пытается запустить рантайм без вызова gophkeeper init.
func TestNew_WhenFileDoesNotExist_ShouldReturnDatabaseMissingError(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Принудительно выставляем права 0700 для папки, чтобы пройти проверки sqlite.Open
	err := os.Chmod(tmpDir, 0o700)
	require.NoError(t, err)

	// Наполняем подструктуры через фабричный метод пакета config
	appCfg := config.NewAppConfig("", "")
	storageCfg := config.NewStorageConfig(filepath.Join(tmpDir, "non_existent_vault.db"))
	loggingCfg := config.NewLoggingConfig("", "", "")
	cfg := config.NewConfig(appCfg, storageCfg, loggingCfg)

	application, err := New(ctx, cfg)

	assert.ErrorIs(t, err, ErrDatabaseMissing, "Должна вернуться каноничная ошибка отсутствия файла БД")
	assert.Nil(t, application, "Контейнер приложения должен быть nil")
}

// TestShutdown_WithNilApplication_ShouldNotPanic проверяет устойчивость
// деструктора к передаче пустой ссылки.
func TestShutdown_WithNilApplication_ShouldNotPanic(t *testing.T) {
	err := Shutdown(nil)
	assert.NoError(t, err, "Вызов Shutdown(nil) не должен приводить к панике или ошибкам")
}

// TestShutdown_WithValidApplication_ShouldClearResources проверяет, что
// деструктор честно стирает данные конфигурации и закрывает указатели.
func TestShutdown_WithValidApplication_ShouldClearResources(t *testing.T) {
	tmpDir := t.TempDir()

	// Обязательный ИБ-шаг для тестов GophKeeper: принудительно выставляем
	// жесткие права 0700 на временную папку, чтобы пройти валидацию СУБД.
	err := os.Chmod(tmpDir, 0o700)
	require.NoError(t, err)

	dbPath := filepath.Join(tmpDir, "test_shutdown.db")

	// Создаем пустой файл, имитирующий БД, выставляя права 0600
	f, err := os.OpenFile(dbPath, os.O_RDWR|os.O_CREATE, 0o600)
	require.NoError(t, err)
	_ = f.Close()

	// Собираем валидную конфигурацию через конструктор NewConfig
	appCfg := config.NewAppConfig("", "")
	storageCfg := config.NewStorageConfig(dbPath)
	loggingCfg := config.NewLoggingConfig("", "debug", "")
	cfg := config.NewConfig(appCfg, storageCfg, loggingCfg)

	// Инициализируем живое приложение
	application, err := New(context.Background(), cfg)
	require.NoError(t, err, "Приложение должно успешно собраться")
	require.NotNil(t, application)

	// Вызываем очистку ресурсов
	err = Shutdown(application)
	assert.NoError(t, err, "Остановка рантайма должна пройти успешно")

	// Проверяем зануление структуры рантайма с помощью геттеров
	assert.Nil(t, application.DB(), "Указатель на пул соединений СУБД должен быть стерт")
	assert.Empty(t, application.Config().Logging().Level(), "Поля структуры конфигурации должны быть очищены")
}
