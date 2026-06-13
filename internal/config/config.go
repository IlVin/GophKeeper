package config

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	App      AppConfig      `mapstructure:"app"`
	SSHAgent SSHAgentConfig `mapstructure:"ssh_agent"`
}

type AppConfig struct {
	ConfigFile string `mapstructure:"config_file"`
}

type SSHAgentConfig struct {
	SocketPath string `mapstructure:"socket_path"`
}

var ErrSSHAgentSocketPathNotSet = errors.New("ssh auth socket path is not set")

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
