package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     Config
		wantErr error
	}{
		{
			name: "valid configuration",
			cfg: Config{
				SSHAgent: SSHAgentConfig{SocketPath: "/tmp/ssh.sock"},
				Storage:  StorageConfig{SQLitePath: "/tmp/db.sqlite"},
			},
			wantErr: nil,
		},
		{
			name: "missing ssh agent socket path",
			cfg: Config{
				SSHAgent: SSHAgentConfig{SocketPath: "   "},
				Storage:  StorageConfig{SQLitePath: "/tmp/db.sqlite"},
			},
			wantErr: ErrSSHAgentSocketPathNotSet,
		},
		{
			name: "missing sqlite path",
			cfg: Config{
				SSHAgent: SSHAgentConfig{SocketPath: "/tmp/ssh.sock"},
				Storage:  StorageConfig{SQLitePath: ""},
			},
			wantErr: ErrSQLitePathNotSet,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
