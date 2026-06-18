package config

import "errors"

type Config struct {
	App      AppConfig      `mapstructure:"app"`
	SSHAgent SSHAgentConfig `mapstructure:"ssh_agent"`
	Storage  StorageConfig  `mapstructure:"storage"`
}

type AppConfig struct {
	ConfigFile string `mapstructure:"config_file"`
}

type SSHAgentConfig struct {
	SocketPath string `mapstructure:"socket_path"`
}

type StorageConfig struct {
	SQLitePath string `mapstructure:"sqlite_path"`
}

var (
	ErrSSHAgentSocketPathNotSet = errors.New("ssh auth socket path is not set")
	ErrSQLitePathNotSet         = errors.New("sqlite path is not set")
)
