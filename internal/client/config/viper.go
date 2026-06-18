package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/adrg/xdg"
	"github.com/spf13/viper"
)

const defaultSQLiteRelativePath = "gophkeeper/goph_keeper.db"

func NewViper() *viper.Viper {
	v := viper.New()

	v.SetEnvPrefix("GOPHKEEPER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("app.config_file", "")
	v.SetDefault("ssh_agent.socket_path", "")
	v.SetDefault("storage.sqlite_path", defaultSQLitePath())

	return v
}

func ReadConfigFile(v *viper.Viper) error {
	configFile := strings.TrimSpace(v.GetString("app.config_file"))
	if configFile == "" {
		return nil
	}

	v.SetConfigFile(configFile)

	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	return nil
}

func LoadFromViper(v *viper.Viper) (Config, error) {
	var cfg Config

	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshal config: %w", err)
	}

	// ИСПРАВЛЕНИЕ: Если путь к сокету SSH-агента остался пустым,
	// пробуем вычитать стандартную системную переменную Linux/macOS.
	if strings.TrimSpace(cfg.SSHAgent.SocketPath) == "" {
		cfg.SSHAgent.SocketPath = os.Getenv("SSH_AUTH_SOCK")
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
