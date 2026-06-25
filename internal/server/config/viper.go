// Package config предоставляет структуры, доменные валидаторы и типы данных
// для централизованного управления конфигурационными параметрами сервера GophKeeper.
package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/viper"
)

var (
	// ErrExplicitConfigMissing возвращается, если явно переданный пользователем файл конфигурации не найден.
	ErrExplicitConfigMissing = errors.New("explicitly provided configuration file does not exist")
)

// NewViper конструирует и настраивает изолированный, потокобезопасный объект Viper.
//
// Устанавливает системный префикс окружения GOPHKEEPER_SERVER и мапит точки в знаки подчеркивания.
func NewViper() *viper.Viper {
	v := viper.New()

	v.SetEnvPrefix("GOPHKEEPER_SERVER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Задаем безопасные санитарные дефолты рантайма
	v.SetDefault("server.config_file", "")
	v.SetDefault("server.bind_http", ":80")
	v.SetDefault("server.bind_grpc", ":443")
	v.SetDefault("server.lets_encrypt_domain", "")
	v.SetDefault("server.use_proxy_protocol", false)
	v.SetDefault("server.server_name", "")

	v.SetDefault("storage.postgres_dsn", "")
	v.SetDefault("storage.max_conns", int32(20))
	v.SetDefault("storage.min_conns", int32(2))

	v.SetDefault("pki.server_ca_key_path", "")
	v.SetDefault("pki.device_ca_key_path", "")

	return v
}

// ReadConfigFile осуществляет контролируемое считывание параметров с диска.
//
// Реализует ИБ-барьер Fail-Fast: если путь к файлу задан явно, его физическое
// отсутствие или ошибка парсинга вызовет жесткую остановку сервера.
func ReadConfigFile(v *viper.Viper) error {
	configFile := strings.TrimSpace(v.GetString("server.config_file"))
	if configFile == "" {
		slog.Debug("Configuration file path is empty, relying entirely on environment variables and flags")
		return nil
	}

	slog.Debug("Attempting to parse explicit configuration file",
		slog.String("path", configFile),
	)
	v.SetConfigFile(configFile)

	if err := v.ReadInConfig(); err != nil {
		// Явный переданный файл обязан существовать. Немой запуск заблокирован.
		if errors.Is(err, os.ErrNotExist) {
			slog.ErrorContext(context.Background(), "Critical initialization failure: explicit config file not found",
				slog.String("path", configFile),
			)
			return fmt.Errorf("%w: %s", ErrExplicitConfigMissing, configFile)
		}

		var configFileNotFoundErr viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundErr) {
			slog.ErrorContext(context.Background(), "Critical initialization failure: viper config resolution failed",
				slog.String("path", configFile),
			)
			return fmt.Errorf("%w: %s", ErrExplicitConfigMissing, configFile)
		}

		slog.ErrorContext(context.Background(), "Failed to parse configuration file syntax structure",
			slog.String("path", configFile),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to read config file layout: %w", err)
	}

	slog.Debug("Configuration file successfully read and aggregated",
		slog.String("path", configFile),
	)
	return nil
}

// LoadFromViper десериализует сагрегированные параметры в типизированную структуру Config
// и принудительно прогоняет её через доменные инварианты метода Validate().
func LoadFromViper(v *viper.Viper) (Config, error) {
	var cfg Config

	slog.Debug("Unmarshaling internal viper map to domain Config structure")
	if err := v.Unmarshal(&cfg); err != nil {
		slog.ErrorContext(context.Background(), "Viper structure unmarshal extraction failed",
			slog.Any("error", err),
		)
		return Config{}, fmt.Errorf("failed to unmarshal configuration map: %w", err)
	}

	// Запуск сквозного ИБ-контроля на пустые DSN, порты и крипто-ключи
	if err := cfg.Validate(); err != nil {
		slog.ErrorContext(context.Background(), "Domain configuration validation check constraint failed",
			slog.Any("error", err),
		)
		return Config{}, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}
