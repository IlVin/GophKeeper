package config

import (
	"fmt"
	"strings"

	"github.com/adrg/xdg"
	"github.com/spf13/viper"
)

const defaultSQLiteRelativePath = "gophkeeper/goph_keeper.db"

func NewViper() (*viper.Viper, error) {
	v := viper.New()

	v.SetEnvPrefix("GOPHKEEPER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.BindEnv("ssh.auth_sock", "SSH_AUTH_SOCK"); err != nil {
		return nil, fmt.Errorf("bind env ssh.auth_sock: %w", err)
	}

	v.SetConfigName("gophkeeper")
	v.SetConfigType("yaml")

	v.AddConfigPath(xdg.ConfigHome + "/gophkeeper")
	v.AddConfigPath(".")

	for _, dir := range xdg.ConfigDirs {
		v.AddConfigPath(dir + "/gophkeeper")
	}

	v.SetDefault("storage.sqlite_path", defaultSQLitePath())

	return v, nil
}

func ReadConfigFile(v *viper.Viper) error {
	configFile := strings.TrimSpace(v.GetString("app.config_file"))
	if configFile != "" {
		v.SetConfigFile(configFile)

		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("read config file %q: %w", configFile, err)
		}

		return nil
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
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
