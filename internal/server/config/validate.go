package config

import "strings"

func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.BindGRPC) == "" {
		return ErrServerBindGRPCEmpty
	}

	if strings.TrimSpace(c.Storage.PostgresDSN) == "" {
		return ErrPostgresDSNEmpty
	}

	// Если не используется Let's Encrypt, то для локального TLS 1.3 обязательны внешние ключи CA
	if strings.TrimSpace(c.Server.LetsEncryptDomain) == "" {
		if strings.TrimSpace(c.PKI.ServerCAKeyPath) == "" {
			return ErrServerCAKeyEmpty
		}
		if strings.TrimSpace(c.PKI.DeviceCAKeyPath) == "" {
			return ErrDeviceCAKeyEmpty
		}
		if strings.TrimSpace(c.PKI.DeviceCACertPath) == "" {
			return ErrDeviceCACertEmpty
		}
	}

	// Жесткое правило: --bind-http работает только совместно с --lets-encrypt
	if strings.TrimSpace(c.Server.LetsEncryptDomain) == "" {
		c.Server.BindHTTP = ""
	}

	return nil
}
