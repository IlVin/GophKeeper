package certs

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerCAPEM_ValidCertificate(t *testing.T) {
	pemBytes := ServerCAPEM()
	require.NotEmpty(t, pemBytes, "Embedded Server CA bytes must not be empty. Run 'make gen-ca' first.")

	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "Server CA must be a valid PEM block")
	assert.Equal(t, "CERTIFICATE", block.Type, "PEM block type must be CERTIFICATE")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Server CA bytes must be parseable into x509 Certificate")
	assert.True(t, cert.IsCA, "Server CA must have IsCA flag set to true")
}

func TestDeviceCAPEM_ValidCertificate(t *testing.T) {
	pemBytes := DeviceCAPEM()
	require.NotEmpty(t, pemBytes, "Embedded Device CA bytes must not be empty. Run 'make gen-ca' first.")

	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "Device CA must be a valid PEM block")
	assert.Equal(t, "CERTIFICATE", block.Type, "PEM block type must be CERTIFICATE")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Device CA bytes must be parseable into x509 Certificate")
	assert.True(t, cert.IsCA, "Device CA must have IsCA flag set to true")
}
