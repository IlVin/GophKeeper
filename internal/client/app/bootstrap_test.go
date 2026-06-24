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

	assert.ErrorIs(t, err, ErrDatabaseMissing, "should return canonical database missing error")
	assert.Nil(t, application, "application container should be nil")
}

// TestShutdown_WithNilApplication_ShouldNotPanic проверяет устойчивость
// деструктора к передаче пустой ссылки.
func TestShutdown_WithNilApplication_ShouldNotPanic(t *testing.T) {
	err := Shutdown(nil)
	assert.NoError(t, err, "calling Shutdown(nil) should not panic or error")
}

// TestShutdown_WithValidApplication_ShouldClearResources проверяет, что
// деструктор честно стирает данные конфигурации и закрывает указатели.
func TestShutdown_WithValidApplication_ShouldClearResources(t *testing.T) {
	tmpDir := t.TempDir()

	// Required security step for GophKeeper tests: forcibly setting
	// strict 0700 permissions on temp dir to pass DB validation.
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
	require.NoError(t, err, "application should build successfully")
	require.NotNil(t, application)

	// Вызываем очистку ресурсов
	err = Shutdown(application)
	assert.NoError(t, err, "runtime shutdown should succeed")

	// Проверяем зануление структуры рантайма с помощью геттеров
	assert.Nil(t, application.DB(), "database connection pool pointer should be cleared")
	assert.Empty(t, application.Config().Logging().Level(), "config struct fields should be cleared")
}
