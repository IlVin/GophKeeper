package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestConfig_Validate проверяет матрицу условий валидатора конфигурации.
// Тестирует обязательность пути СУБД, валидность уровней и форматов slog-логов.
func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		app         AppConfig
		storage     StorageConfig
		logging     LoggingConfig
		expectedErr error
	}{
		{
			name: "Успешная валидация со всеми корректными параметрами",
			app: AppConfig{
				configFile:    "config.yaml",
				defaultServer: "localhost:443",
			},
			storage: StorageConfig{
				sqlitePath: "/tmp/gophkeeper.db",
			},
			logging: LoggingConfig{
				logFile: "/tmp/client.log",
				level:   "debug",
				format:  "json",
			},
			expectedErr: nil,
		},
		{
			name: "Ошибка валидации при пустом пути к SQLite базе данных",
			storage: StorageConfig{
				sqlitePath: "   ", // Пробелы должны триммиться
			},
			logging: LoggingConfig{
				level:  "info",
				format: "text",
			},
			expectedErr: ErrSQLitePathNotSet,
		},
		{
			name: "Ошибка валидации при некорректном уровне логирования",
			storage: StorageConfig{
				sqlitePath: "/tmp/goph.db",
			},
			logging: LoggingConfig{
				level:  "trace-invalid",
				format: "text",
			},
			expectedErr: ErrInvalidLogLevel,
		},
		{
			name: "Ошибка валидации при некорректном формате вывода логов",
			storage: StorageConfig{
				sqlitePath: "/tmp/goph.db",
			},
			logging: LoggingConfig{
				level:  "info",
				format: "xml-invalid",
			},
			expectedErr: ErrInvalidLogFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewConfig(tt.app, tt.storage, tt.logging)
			err := cfg.Validate()

			if tt.expectedErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.expectedErr)
			}
		})
	}
}
