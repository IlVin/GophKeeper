package pki

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGenerateDynamicServerCertificate_FailsIfInputsInvalid проверяет защиту фабрики
// динамического выпуска серверных сертификатов от паник при передаче пустых аргументов.
func TestGenerateDynamicServerCertificate_FailsIfInputsInvalid(t *testing.T) {
	cert, err := GenerateDynamicServerCertificate(nil, nil, "")

	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "ca certificates and private keys cannot be nil")
}

// TestGenerateDynamicServerCertificate_FailsIfHostMissing проверяет барьер отсутствия хоста.
func TestGenerateDynamicServerCertificate_FailsIfHostMissing(t *testing.T) {
	cert, err := GenerateDynamicServerCertificate(nil, nil, "localhost")

	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Contains(t, err.Error(), "ca certificates and private keys cannot be nil")
}
