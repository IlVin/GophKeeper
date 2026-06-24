// Package config предоставляет инструменты для персистентного сохранения
// настроек конфигурации клиента GophKeeper на диск.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// configDTO определяет промежуточную структуру для красивой сериализации
// параметров конфигурации в формат YAML, обходя ограничения инкапсуляции приватных полей.
type configDTO struct {
	App     appDTO     `yaml:"app"`
	Storage storageDTO `yaml:"storage"`
	Logging loggingDTO `yaml:"logging"`
}

type appDTO struct {
	DefaultServer string `yaml:"default_server"`
}

type storageDTO struct {
	SQLitePath string `yaml:"sqlite_path"`
}

type loggingDTO struct {
	LogFile string `yaml:"log_file"`
	Level   string `yaml:"level"`
	Format  string `yaml:"format"`
}

// WriteDefaultConfigFile атомарно создает директорию и записывает файл конфигурации по умолчанию.
//
// Если файл по указанному пути уже существует на диске, функция прерывает выполнение
// без перезаписи данных, предотвращая затирание пользовательских настроек.
// Для записи выставляются строгие ИБ-права доступа: 0700 на папки и 0600 на файл.
func WriteDefaultConfigFile(path string, cfg Config) error {
	path = strings.TrimSpace(path)
	if path == "" {
		slog.Debug("Config write request rejected: empty path provided")
		return nil
	}

	dir := filepath.Dir(path)
	slog.Debug("Preparing directory for config file", "dir", dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Error("Failed to create config directory", "dir", dir, "error", err)
		return fmt.Errorf("create config directory %q: %w", dir, err)
	}

	// Если конфиг уже существует, защищаем пользовательские правки от перезаписи
	if _, err := os.Stat(path); err == nil {
		slog.Debug("Default config write skipped: file already exists on disk")
		return nil
	} else if !os.IsNotExist(err) {
		slog.Error("Failed to check config file status", "path", path, "error", err)
		return fmt.Errorf("check config file status %q: %w", path, err)
	}

	// Наполняем экспортируемую DTO-структуру из иммутабельных геттеров
	dto := configDTO{
		App: appDTO{
			DefaultServer: cfg.App().DefaultServer(),
		},
		Storage: storageDTO{
			SQLitePath: cfg.Storage().SQLitePath(),
		},
		Logging: loggingDTO{
			LogFile: cfg.Logging().LogFile(),
			Level:   cfg.Logging().Level(),
			Format:  cfg.Logging().Format(),
		},
	}

	// Честный маршалинг структуры со всеми отступами
	content, err := yaml.Marshal(dto)
	if err != nil {
		slog.Error("Critical config YAML serialization error", "error", err)
		return fmt.Errorf("marshal config to yaml: %w", err)
	}

	slog.Debug("Writing config params to disk with strict 0600 permissions")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		slog.Error("Failed to write config file to disk", "path", path, "error", err)
		return fmt.Errorf("write config file %q: %w", path, err)
	}

	slog.Info("Default config file successfully generated")
	return nil
}
