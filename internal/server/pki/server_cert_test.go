package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"gophkeeper/internal/server/pki"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func helperGenerateCAKeyPair(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName: "GophKeeper Test CA",
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(10 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert, privKey
}

func TestGenerateDynamicServerCertificate_Success(t *testing.T) {
	caCert, caKey := helperGenerateCAKeyPair(t)

	tlsCert, err := pki.GenerateDynamicServerCertificate(caCert, caKey, "gophkeeper.local")
	require.NoError(t, err)
	require.NotNil(t, tlsCert)
	require.Len(t, tlsCert.Certificate, 2) // Листовой + CA

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)

	assert.Equal(t, "gophkeeper.local", leaf.Subject.CommonName)
	assert.Contains(t, leaf.DNSNames, "gophkeeper.local")
	assert.Contains(t, leaf.DNSNames, "localhost")
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.NotContains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

func TestGenerateDynamicServerCertificate_ValidationErrors(t *testing.T) {
	caCert, caKey := helperGenerateCAKeyPair(t)

	_, err := pki.GenerateDynamicServerCertificate(nil, caKey, "localhost")
	assert.ErrorContains(t, err, "ca certificates and private keys cannot be nil")

	_, err = pki.GenerateDynamicServerCertificate(caCert, caKey, "")
	assert.ErrorContains(t, err, "target server host cannot be empty")
}
