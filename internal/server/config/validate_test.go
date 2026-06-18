package config_test

import (
	"testing"

	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		buildCh func(c *config.Config)
		wantErr error
	}{
		{
			name: "valid configuration with PKI paths",
			buildCh: func(c *config.Config) {
				c.Server.BindGRPC = ":443"
				c.Storage.PostgresDSN = "postgres://localhost:5432/db"
				c.PKI.ServerCAKeyPath = "/etc/certs/server.key"
				c.PKI.DeviceCAKeyPath = "/etc/certs/device.key"
				c.PKI.DeviceCACertPath = "/etc/certs/device.crt"
			},
			wantErr: nil,
		},
		{
			name: "missing grpc bind address",
			buildCh: func(c *config.Config) {
				c.Server.BindGRPC = ""
				c.Storage.PostgresDSN = "postgres://localhost:5432/db"
			},
			wantErr: config.ErrServerBindGRPCEmpty,
		},
		{
			name: "missing postgres dsn",
			buildCh: func(c *config.Config) {
				c.Server.BindGRPC = ":443"
				c.Storage.PostgresDSN = ""
			},
			wantErr: config.ErrPostgresDSNEmpty,
		},
		{
			name: "missing server ca key path when ACME disabled",
			buildCh: func(c *config.Config) {
				c.Server.BindGRPC = ":443"
				c.Storage.PostgresDSN = "postgres://localhost:5432/db"
				c.PKI.ServerCAKeyPath = ""
			},
			wantErr: config.ErrServerCAKeyEmpty,
		},
		{
			name: "missing device ca key path when ACME disabled",
			buildCh: func(c *config.Config) {
				c.Server.BindGRPC = ":443"
				c.Storage.PostgresDSN = "postgres://localhost:5432/db"
				c.PKI.ServerCAKeyPath = "/etc/certs/server.key"
				c.PKI.DeviceCAKeyPath = ""
			},
			wantErr: config.ErrDeviceCAKeyEmpty,
		},
		{
			name: "missing device ca cert path when ACME disabled",
			buildCh: func(c *config.Config) {
				c.Server.BindGRPC = ":443"
				c.Storage.PostgresDSN = "postgres://localhost:5432/db"
				c.PKI.ServerCAKeyPath = "/etc/certs/server.key"
				c.PKI.DeviceCAKeyPath = "/etc/certs/device.key"
				c.PKI.DeviceCACertPath = ""
			},
			wantErr: config.ErrDeviceCACertEmpty,
		},
		{
			name: "valid with lets encrypt domain and empty PKI paths",
			buildCh: func(c *config.Config) {
				c.Server.BindGRPC = ":443"
				c.Storage.PostgresDSN = "postgres://localhost:5432/db"
				c.Server.LetsEncryptDomain = "example.com"
				c.PKI.ServerCAKeyPath = ""
				c.PKI.DeviceCAKeyPath = ""
				c.PKI.DeviceCACertPath = ""
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg config.Config
			tt.buildCh(&cfg)
			err := cfg.Validate()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
