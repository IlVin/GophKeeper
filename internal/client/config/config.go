package config

import "errors"

type Config struct {
	App     AppConfig     `mapstructure:"app"`
	SSH     SSHConfig     `mapstructure:"ssh"`
	Storage StorageConfig `mapstructure:"storage"`
}

type AppConfig struct {
	ConfigFile string `mapstructure:"config_file"`
}

type SSHConfig struct {
	AuthSock string `mapstructure:"auth_sock"`
}

type StorageConfig struct {
	SQLitePath string `mapstructure:"sqlite_path"`
}

var (
	ErrSQLitePathNotSet = errors.New("sqlite path is not set")
)
