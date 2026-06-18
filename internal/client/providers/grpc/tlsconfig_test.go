package grpc

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigForBootstrap_Success(t *testing.T) {
	t.Parallel()

	cfg, err := ConfigForBootstrap()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Nil(t, cfg.Certificates)
	assert.NotNil(t, cfg.RootCAs)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

func TestConfigForMTLS_DefaultPoolFallback(t *testing.T) {
	t.Parallel()

	mockCert := tls.Certificate{}
	cfg, err := ConfigForMTLS(mockCert, nil) // Передаем nil для проверки триггера fallback
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.NotNil(t, cfg.RootCAs)
	assert.Len(t, cfg.Certificates, 1)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

func TestConfigForTest_BypassesVerification(t *testing.T) {
	t.Parallel()

	cfg := ConfigForTest()
	require.NotNil(t, cfg)
	assert.True(t, cfg.InsecureSkipVerify)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}
