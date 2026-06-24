package device_test

import (
	"crypto/x509"
	"testing"

	"gophkeeper/internal/client/providers/device"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateContainerCSR_Success_And_ParsingVerification проверяет сквозной
// цикл генерации CSR, верифицируя структуру x509.CertificateRequest и наличие SAN URN.
func TestGenerateContainerCSR_Success_And_ParsingVerification(t *testing.T) {
	targetDeviceID := "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"

	// Вызываем генератор паспорта
	rawPriv, csrBytes, err := device.GenerateContainerCSR(targetDeviceID)

	require.NoError(t, err, "CSR generation should not return errors")
	require.NotEmpty(t, rawPriv, "PKCS8 private key binary array must not be empty")
	require.NotEmpty(t, csrBytes, "CSR DER binary block must not be empty")

	// Десериализуем получившийся CSR средствами стандартной библиотеки x509 для валидации структуры
	csr, err := x509.ParseCertificateRequest(csrBytes)
	require.NoError(t, err, "Received blob must parse successfully as x509 Certificate Request")

	// 1. Проверяем строгое соответствие CommonName переданному UUID
	expectedCN := "GophKeeper Client Container " + targetDeviceID
	assert.Equal(t, expectedCN, csr.Subject.CommonName)

	// 2. Проверяем фиксацию криптографического алгоритма подписи
	assert.Equal(t, x509.ECDSAWithSHA256, csr.SignatureAlgorithm, "CSR signature algorithm must be strictly ECDSA-SHA256")

	// 3. Проверяем ИБ-инвариант mTLS: наличие защитного идентификатора контейнера в SAN URIs
	require.Len(t, csr.URIs, 1, "Request must contain exactly one SAN URI")
	assert.Equal(t, "urn:gophkeeper:file:"+targetDeviceID, csr.URIs[0].String(), "Embedded URN must exactly match canonical container format")
}
