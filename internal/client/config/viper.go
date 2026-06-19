package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/adrg/xdg"
	"github.com/spf13/viper"
)

const (
	defaultConfigRelativePath = "gophkeeper/config.yaml"
	defaultSQLiteRelativePath = "gophkeeper/goph_keeper.db"
)

func NewViper() (*viper.Viper, error) {
	v := viper.New()

	v.SetEnvPrefix("GOPHKEEPER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetConfigName("gophkeeper")
	v.SetConfigType("yaml")

	v.AddConfigPath(xdg.ConfigHome + "/gophkeeper")
	v.AddConfigPath(".")

	for _, dir := range xdg.ConfigDirs {
		v.AddConfigPath(dir + "/gophkeeper")
	}

	v.SetDefault("app.config_file", defaultConfigPath())
	v.SetDefault("storage.sqlite_path", defaultSQLitePath())
	v.SetDefault("logging.log_file", defaultLogPath())
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "text")

	return v, nil
}

func ReadConfigFile(v *viper.Viper) error {
	configFile := strings.TrimSpace(v.GetString("app.config_file"))

	if configFile != "" {
		v.SetConfigFile(configFile)

		if err := v.ReadInConfig(); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil // Отсутствие конфига — это нормально
			}

			// На случай, если Viper все же обернул её в свой тип
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				return nil
			}

			return fmt.Errorf("read config file %q: %w", configFile, err)
		}

		return nil
	}

	// Ветка, если путь ищется по дефолтным путям AddConfigPath
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("read config file: %w", err)
	}

	return nil
}

func LoadFromViper(v *viper.Viper) (Config, error) {
	var cfg Config

	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

func defaultConfigPath() string {
	return defaultConfigPathFromFunc(xdg.ConfigFile)
}

func defaultConfigPathFromFunc(configFile func(string) (string, error)) string {
	path, err := configFile(defaultConfigRelativePath)
	if err != nil {
		return ""
	}

	return path
}

func defaultSQLitePath() string {
	return defaultSQLitePathFromFunc(xdg.StateFile)
}

func defaultSQLitePathFromFunc(stateFile func(string) (string, error)) string {
	path, err := stateFile(defaultSQLiteRelativePath)
	if err != nil {
		return ""
	}

	return path
}

func defaultLogPath() string {
	// Используем XDG State спецификацию (для логов и истории)
	path, err := xdg.StateFile("gophkeeper/client.log")
	if err != nil {
		return ""
	}
	return path
}
