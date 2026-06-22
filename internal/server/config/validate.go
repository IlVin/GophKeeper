package config

import "strings"

func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.BindGRPC) == "" {
		return ErrServerBindGRPCEmpty
	}

	if strings.TrimSpace(c.Storage.PostgresDSN) == "" {
		return ErrPostgresDSNEmpty
	}

	if strings.TrimSpace(c.Server.LetsEncryptDomain) == "" {
		if strings.TrimSpace(c.PKI.ServerCAKeyPath) == "" {
			return ErrServerCAKeyEmpty
		}
		if strings.TrimSpace(c.PKI.DeviceCAKeyPath) == "" {
			return ErrDeviceCAKeyEmpty
		}
	}

	if strings.TrimSpace(c.Server.LetsEncryptDomain) == "" {
		c.Server.BindHTTP = ""
	}

	return nil
}
