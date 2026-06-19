package config

import "errors"

type Config struct {
	App     AppConfig     `mapstructure:"app"`
	Storage StorageConfig `mapstructure:"storage"`
	Logging LoggingConfig `mapstructure:"logging" yaml:"logging"`
}

type AppConfig struct {
	ConfigFile string `mapstructure:"config_file" yaml:"-" json:"-"`
}

type StorageConfig struct {
	SQLitePath string `mapstructure:"sqlite_path"`
}

type LoggingConfig struct {
	LogFile string `mapstructure:"log_file" yaml:"log_file"`
	Level   string `mapstructure:"level" yaml:"level"`
	Format  string `mapstructure:"format" yaml:"format"`
}

var (
	ErrSQLitePathNotSet = errors.New("sqlite path is not set")
)
