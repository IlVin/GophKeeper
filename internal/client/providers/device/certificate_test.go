package device

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper для генерации тестовой пары ключей и сертификата в памяти
func createTestCertKeyPair(t *testing.T, includeClientAuth bool) (certPEM, keyPEM []byte) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if includeClientAuth {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"GophKeeper Test Device"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  extKeyUsage,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func TestLoadDeviceCertificate_Success(t *testing.T) {
	t.Parallel()
	certBytes, keyBytes := createTestCertKeyPair(t, true)

	cert, err := LoadDeviceCertificate(certBytes, keyBytes)
	require.NoError(t, err)
	assert.NotEmpty(t, cert.Certificate)
	assert.NotNil(t, cert.PrivateKey)
}

func TestLoadDeviceCertificate_MissingClientAuth(t *testing.T) {
	t.Parallel()
	certBytes, keyBytes := createTestCertKeyPair(t, false) // Без clientAuth

	_, err := LoadDeviceCertificate(certBytes, keyBytes)
	assert.ErrorContains(t, err, "certificate missing clientAuth ExtendedKeyUsage")
}

func TestLoadDeviceCertificate_MalformedPEM(t *testing.T) {
	t.Parallel()
	_, err := LoadDeviceCertificate([]byte("invalid cert"), []byte("invalid key"))
	assert.ErrorContains(t, err, "parse X509 key pair")
}

func TestEncapsulateDeviceCertificate_Success(t *testing.T) {
	t.Parallel()
	certBytes, keyBytes := createTestCertKeyPair(t, true)

	origCert, err := tls.X509KeyPair(certBytes, keyBytes)
	require.NoError(t, err)

	encCertPEM, encKeyPEM, err := EncapsulateDeviceCertificate(origCert)
	require.NoError(t, err)
	assert.NotEmpty(t, encCertPEM)
	assert.NotEmpty(t, encKeyPEM)

	// Проверяем, что сериализованный PKCS#8 обратно парсится корректно
	block, _ := pem.Decode(encKeyPEM)
	require.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)
}

func TestEncapsulateDeviceCertificate_NoPrivateKey(t *testing.T) {
	t.Parallel()
	certBytes, _ := createTestCertKeyPair(t, true)

	// Создаем tls.Certificate без приватного ключа
	cert := tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  nil,
	}

	_, _, err := EncapsulateDeviceCertificate(cert)
	assert.ErrorIs(t, err, ErrNoPrivateKey)
}
