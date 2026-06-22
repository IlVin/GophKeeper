package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConfigGetters_ShouldReturnCorrectValues проверяет, что конструктор
// NewConfig и фабричные функции подструктур корректно инициализируют параметры,
// а иммутабельные геттеры возвращают точные копии данных без риска модификации.
func TestConfigGetters_ShouldReturnCorrectValues(t *testing.T) {
	// Инициализируем подструктуры строго через новые каноничные фабричные функции
	appCfg := NewAppConfig("/etc/gophkeeper.yaml", "gophkeeper.internal:443")
	storageCfg := NewStorageConfig("/var/lib/gophkeeper.db")
	loggingCfg := NewLoggingConfig("/var/log/gophkeeper.log", "debug", "json")

	// Сборка корневого контейнера конфигурации
	cfg := NewConfig(appCfg, storageCfg, loggingCfg)

	// Проверяем неизменяемый доступ через интерфейс геттеров доменной модели
	assert.Equal(t, "/etc/gophkeeper.yaml", cfg.App().ConfigFile(), "Путь к файлу конфигурации должен совпадать")
	assert.Equal(t, "gophkeeper.internal:443", cfg.App().DefaultServer(), "Сетевой адрес gRPC-сервера должен совпадать")
	assert.Equal(t, "/var/lib/gophkeeper.db", cfg.Storage().SQLitePath(), "Путь к СУБД SQLite должен совпадать")
	assert.Equal(t, "/var/log/gophkeeper.log", cfg.Logging().LogFile(), "Путь к файлу логов должен совпадать")
	assert.Equal(t, "debug", cfg.Logging().Level(), "Уровень логирования должен совпадать")
	assert.Equal(t, "json", cfg.Logging().Format(), "Формат сериализации логов должен совпадать")
}
