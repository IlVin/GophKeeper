// Package config предоставляет инструменты для инициализации и парсинга
// конфигурации с использованием библиотеки Viper и спецификации директорий XDG.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/adrg/xdg"
	"github.com/spf13/viper"
)

const (
	// Относительные пути по умолчанию в структурах XDG
	defaultConfigRelativePath = "gophkeeper/config.yaml"
	defaultSQLiteRelativePath = "gophkeeper/goph_keeper.db"
)

// NewViper конструирует и подготавливает экземпляр Viper с дефолтными значениями.
//
// Настраивает автоматический подхват переменных окружения с префиксом GOPHKEEPER_,
// подменяя точки в ключах на символы подчеркивания (app.config_file -> GOPHKEEPER_APP_CONFIG_FILE).
func NewViper() (*viper.Viper, error) {
	v := viper.New()

	v.SetEnvPrefix("GOPHKEEPER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetConfigName("gophkeeper")
	v.SetConfigType("yaml")

	// Ранжирование путей поиска конфигурационного файла согласно стандартам ИБ
	v.AddConfigPath(xdg.ConfigHome + "/gophkeeper")
	v.AddConfigPath(".")

	for _, dir := range xdg.ConfigDirs {
		v.AddConfigPath(dir + "/gophkeeper")
	}

	// Установка санитарных дефолтов для бесперебойной автономной работы
	v.SetDefault("app.config_file", defaultConfigPath())
	v.SetDefault("app.default_server", "localhost:443")
	v.SetDefault("storage.sqlite_path", defaultSQLitePath())
	v.SetDefault("logging.log_file", DefaultLogPath())
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "text")

	return v, nil
}

// ReadConfigFile осуществляет контролируемое чтение файла конфигурации YAML с диска.
//
// Если путь к файлу задан явно, Viper пытается прочесть только его. В противном случае
// производится автоматический поиск по путям AddConfigPath. Отсутствие файла не считается ошибкой.
func ReadConfigFile(v *viper.Viper) error {
	if v == nil {
		return errors.New("viper pointer cannot be nil")
	}

	configFile := strings.TrimSpace(v.GetString("app.config_file"))

	if configFile != "" {
		v.SetConfigFile(configFile)
		slog.Debug("Attempting to read config from explicit path", "path", configFile)

		if err := v.ReadInConfig(); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				slog.Debug("Config file missing on disk, using default values")
				return nil
			}
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				slog.Debug("Config file not found, using defaults")
				return nil
			}
			slog.Error("Critical error reading specified config file", "error", err)
			return fmt.Errorf("read config file %q: %w", configFile, err)
		}

		slog.Debug("Config file successfully applied", "used_path", v.ConfigFileUsed())
		return nil
	}

	slog.Debug("No explicit path set, scanning default directories")
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			slog.Debug("Default config files not found, runtime using base settings")
			return nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		slog.Error("Error scanning config paths", "error", err)
		return fmt.Errorf("auto read config: %w", err)
	}

	slog.Debug("Config file automatically found and applied", "used_path", v.ConfigFileUsed())
	return nil
}

// LoadFromViper осуществляет безопасное извлечение и валидацию данных из Viper.
//
// Функция решает проблему наполнения приватных полей структуры Config, собирая её
// через фабричный метод после валидации, исключая дефекты MVP-маршалинга.
func LoadFromViper(v *viper.Viper) (Config, error) {
	if v == nil {
		return Config{}, errors.New("viper pointer cannot be nil")
	}

	slog.Debug("Starting config object graph assembly and validation")

	appCfg := AppConfig{
		configFile:    v.GetString("app.config_file"),
		defaultServer: v.GetString("app.default_server"),
	}

	storageCfg := StorageConfig{
		sqlitePath: v.GetString("storage.sqlite_path"),
	}

	loggingCfg := LoggingConfig{
		logFile: v.GetString("logging.log_file"),
		level:   v.GetString("logging.level"),
		format:  v.GetString("logging.format"),
	}

	cfg := NewConfig(appCfg, storageCfg, loggingCfg)

	// Вызов внешнего валидатора (бизнес-правила)
	if err := cfg.Validate(); err != nil {
		slog.Error("Config parameter validation failed", "error", err)
		return Config{}, fmt.Errorf("validate params: %w", err)
	}

	slog.Debug("Config assembly completed successfully, invariants satisfied")
	return cfg, nil
}

// defaultConfigPath вычисляет системный путь для файла конфигурации
func defaultConfigPath() string {
	return defaultConfigPathFromFunc(xdg.ConfigFile)
}

func defaultConfigPathFromFunc(configFile func(string) (string, error)) string {
	path, err := configFile(defaultConfigRelativePath)
	if err != nil {
		slog.Debug("XDG spec could not determine config path, using stub", "error", err)
		return ""
	}
	return path
}

// defaultSQLitePath вычисляет системный путь по умолчанию для зашифрованной СУБД
func defaultSQLitePath() string {
	return defaultSQLitePathFromFunc(xdg.StateFile)
}

func defaultSQLitePathFromFunc(stateFile func(string) (string, error)) string {
	path, err := stateFile(defaultSQLiteRelativePath)
	if err != nil {
		slog.Debug("XDG spec could not determine state storage path", "error", err)
		return ""
	}
	return path
}

// DefaultLogPath вычисляет системный путь по умолчанию для файла логирования slog.
// Экспортируется для обеспечения бесшовного двухэтапного старта логгера из main.go.
func DefaultLogPath() string {
	path, err := xdg.StateFile("gophkeeper/client.log")
	if err != nil {
		slog.Debug("XDG spec could not determine log file path", "error", err)
		return ""
	}
	return path
}
