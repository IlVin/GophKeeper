// Package config предоставляет структуры, доменные валидаторы и типы данных
// для централизованного управления конфигурационными параметрами сервера GophKeeper.
package config

import (
	"errors"
	"net"
	"strings"
)

// Config инкапсулирует полную иерархическую структуру конфигурации
// облачного сервера, считываемую подсистемой Viper.
type Config struct {
	Server  ServerConfig  `mapstructure:"server"`
	Storage StorageConfig `mapstructure:"storage"`
	PKI     PKIConfig     `mapstructure:"pki"`
}

// ServerConfig координирует параметры сетевых интерфейсов и прокси-протоколов.
type ServerConfig struct {
	ConfigFile        string `mapstructure:"config_file"`
	BindHTTP          string `mapstructure:"bind_http"`
	BindGRPC          string `mapstructure:"bind_grpc"`
	LetsEncryptDomain string `mapstructure:"lets_encrypt_domain"`
	ServerName        string `mapstructure:"server_name"`
	UseProxyProtocol  bool   `mapstructure:"use_proxy_protocol"` // Поддержка PROXY v1/v2 для AWS/Cloudflare шлюзов
}

// StorageConfig управляет строками подключения и лимитами пула соединений PostgreSQL.
type StorageConfig struct {
	PostgresDSN string `mapstructure:"postgres_dsn"`
	MaxConns    int32  `mapstructure:"max_conns"` // Максимальное количество коннектов в пуле pgxpool
	MinConns    int32  `mapstructure:"min_conns"` // Минимальное гарантированное количество коннектов
}

// PKIConfig хранит пути к закрытым ключам и цепочкам CA для динамического выпуска mTLS паспортов.
type PKIConfig struct {
	ServerCAKeyPath string `mapstructure:"server_ca_key_path"`
	DeviceCAKeyPath string `mapstructure:"device_ca_key_path"`
}

var (
	ErrServerBindGRPCEmpty = errors.New("server gRPC bind address is not set")
	ErrPostgresDSNEmpty    = errors.New("postgres dsn is not set")
	ErrServerCAKeyEmpty    = errors.New("server ca private key path is not set")
	ErrServerCACertEmpty   = errors.New("server ca certificate path is not set")
	ErrDeviceCAKeyEmpty    = errors.New("device ca private key path is not set")
	ErrDeviceCACertEmpty   = errors.New("device ca certificate path is not set")
)

// Validate выполняет сквозную Fail-Fast проверку доменных инвариантов серверной конфигурации.
//
// Блокирует старт приложения на первой миллисекунде, если критические пути PKI
// или параметры СУБД переданы некорректно, защищая рантайм от немого падения.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Server.BindGRPC) == "" {
		return ErrServerBindGRPCEmpty
	}
	if strings.TrimSpace(c.Storage.PostgresDSN) == "" {
		return ErrPostgresDSNEmpty
	}
	if strings.TrimSpace(c.PKI.ServerCAKeyPath) == "" {
		return ErrServerCAKeyEmpty
	}
	if strings.TrimSpace(c.PKI.DeviceCAKeyPath) == "" {
		return ErrDeviceCAKeyEmpty
	}

	// Если ServerName не задан явно, извлекаем из BindGRPC
	if strings.TrimSpace(c.Server.ServerName) == "" {
		host, _, err := net.SplitHostPort(c.Server.BindGRPC)
		if err != nil || host == "" {
			c.Server.ServerName = "localhost"
		} else {
			c.Server.ServerName = host
		}
	}

	// Выставляем дефолты пула СУБД, если параметры пропущены
	if c.Storage.MaxConns <= 0 {
		c.Storage.MaxConns = 20
	}
	if c.Storage.MinConns <= 0 {
		c.Storage.MinConns = 2
	}

	return nil
}
