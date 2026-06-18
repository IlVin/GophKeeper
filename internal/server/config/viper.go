package config

import (
	"strings"

	"github.com/spf13/viper"
)

func NewViper() *viper.Viper {
	v := viper.New()

	v.SetEnvPrefix("GOPHKEEPER_SERVER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("server.config_file", "")
	v.SetDefault("server.bind_http", ":80")
	v.SetDefault("server.bind_grpc", ":443")
	v.SetDefault("server.lets_encrypt_domain", "")
	v.SetDefault("storage.postgres_dsn", "")

	// Дефолтные значения путей PKI (могут переопределяться через флаги, env или yaml)
	v.SetDefault("pki.server_ca_key_path", "")
	v.SetDefault("pki.device_ca_key_path", "")
	v.SetDefault("pki.device_ca_cert_path", "")

	return v
}

func ReadConfigFile(v *viper.Viper) error {
	configFile := strings.TrimSpace(v.GetString("server.config_file"))
	if configFile == "" {
		return nil
	}

	v.SetConfigFile(configFile)
	return v.ReadInConfig()
}

func LoadFromViper(v *viper.Viper) (Config, error) {
	var cfg Config

	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
