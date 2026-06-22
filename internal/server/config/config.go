package config

import "errors"

type Config struct {
	Server  ServerConfig  `mapstructure:"server"`
	Storage StorageConfig `mapstructure:"storage"`
	PKI     PKIConfig     `mapstructure:"pki"`
}

type ServerConfig struct {
	ConfigFile        string `mapstructure:"config_file"`
	BindHTTP          string `mapstructure:"bind_http"`
	BindGRPC          string `mapstructure:"bind_grpc"`
	LetsEncryptDomain string `mapstructure:"lets_encrypt_domain"`
	UseProxyProtocol  bool   `mapstructure:"use_proxy_protocol"` // ДОБАВЛЕНО
}

type StorageConfig struct {
	PostgresDSN string `mapstructure:"postgres_dsn"`
}

type PKIConfig struct {
	ServerCAKeyPath string `mapstructure:"server_ca_key_path"`
	DeviceCAKeyPath string `mapstructure:"device_ca_key_path"`
}

var (
	ErrServerBindGRPCEmpty = errors.New("server gRPC bind address is not set")
	ErrPostgresDSNEmpty    = errors.New("postgres dsn is not set")
	ErrServerCAKeyEmpty    = errors.New("server ca private key path is not set")
	ErrServerCACertEmpty   = errors.New("server ca certificate path is not set") // ДОБАВЛЕНО
	ErrDeviceCAKeyEmpty    = errors.New("device ca private key path is not set")
	ErrDeviceCACertEmpty   = errors.New("device ca certificate path is not set")
)
