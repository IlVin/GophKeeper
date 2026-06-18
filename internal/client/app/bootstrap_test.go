package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gophkeeper/internal/client/config"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBootstrap_TemporaryFileWorkflow(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// ЯВНОЕ ИСПРАВЛЕНИЕ: Принудительно перезаписываем маску ОС,
	// выставляя на родительскую папку строгие 0700, требуемые валидатором.
	err := os.Chmod(tmpDir, 0700)
	require.NoError(t, err, "Failed to enforce secure 0700 permissions on temp directory")

	secureDBPath := filepath.Join(tmpDir, "goph_keeper.db")

	v := viper.New()
	v.Set("storage.sqlite_path", secureDBPath)
	v.Set("ssh_agent.socket_path", "/mock/ssh.sock")

	// Запуск бутстрапа поверх изолированного и теперь гарантированно безопасного файла
	ctx, application, err := Bootstrap(context.Background(), v)
	require.NoError(t, err, "Bootstrap must succeed when files are created inside an explicitly secure 0700 folder")
	require.NotNil(t, application)
	assert.NotNil(t, application.DB)

	// Проверяем связь рантайма и бутстрапа через контекст
	extracted, err := AppFromContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, application, extracted)

	// Корректное завершение жизненного цикла
	err = Shutdown(application)
	assert.NoError(t, err)
}

func TestShutdown_SafeWithNilAppAndDB(t *testing.T) {
	t.Parallel()

	// Инвариант: Shutdown не должен падать, если контейнер nil
	err := Shutdown(nil)
	assert.NoError(t, err)

	// Инвариант: Shutdown не должен падать, если дескриптор базы nil
	appWithoutDB := NewApp(config.Config{}, nil)
	err = Shutdown(appWithoutDB)
	assert.NoError(t, err)
}
