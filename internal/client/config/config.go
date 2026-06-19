package config

import "errors"

type Config struct {
	App     AppConfig     `mapstructure:"app"`
	Storage StorageConfig `mapstructure:"storage"`
}

type AppConfig struct {
	ConfigFile string `mapstructure:"config_file"`
}

type StorageConfig struct {
	SQLitePath string `mapstructure:"sqlite_path"`
}

var (
	ErrSQLitePathNotSet = errors.New("sqlite path is not set")
)
