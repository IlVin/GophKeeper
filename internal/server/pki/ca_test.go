package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gophkeeper/internal/server/config"
	"gophkeeper/internal/server/pki"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func helperGenerateMockPrivateKeyPEM(t *testing.T) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	bytes, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: bytes})
}

func helperGenerateMockCertPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Mock CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestLoadServerCA_MissingConfig(t *testing.T) {
	var cfg config.Config
	cfg.PKI.ServerCAKeyPath = ""

	_, _, err := pki.LoadServerCA(cfg)
	assert.ErrorContains(t, err, "server ca private key path is not configured")
}

func TestLoadDeviceCA_FullWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "device.key")
	certPath := filepath.Join(tmpDir, "device.crt")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyBytes, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0600)
	require.NoError(t, err)

	certBytes := helperGenerateMockCertPEM(t, key)
	err = os.WriteFile(certPath, certBytes, 0600)
	require.NoError(t, err)

	var cfg config.Config
	cfg.PKI.DeviceCAKeyPath = keyPath
	cfg.PKI.DeviceCACertPath = certPath

	cert, pkey, err := pki.LoadDeviceCA(cfg)
	require.NoError(t, err)
	assert.NotNil(t, cert)
	assert.NotNil(t, pkey)
	assert.Equal(t, "Mock CA", cert.Subject.CommonName)
}
