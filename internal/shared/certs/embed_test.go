package certs_test

import (
	"encoding/pem"
	"testing"

	"gophkeeper/internal/shared/certs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmbed_ServerCAPEM_ShouldBeValidPEM проверяет синтаксическую корректность
// и наличие валидных маркеров x509 внутри встроенного файла Server CA.
func TestEmbed_ServerCAPEM_ShouldBeValidPEM(t *testing.T) {
	pemBytes := certs.ServerCAPEM()
	require.NotEmpty(t, pemBytes, "Встроенный файл server-ca.crt не должен быть пустым")

	block, rest := pem.Decode(pemBytes)
	require.NotNil(t, block, "Байты Server CA должны успешно декодироваться парсером PEM")
	assert.Equal(t, "CERTIFICATE", block.Type, "Тип PEM блока обязан быть строго CERTIFICATE")
	assert.Empty(t, rest, "Файл не должен содержать мусорных непарсенных хвостов данных")
}

// TestEmbed_DeviceCAPEM_ShouldBeValidPEM проверяет валидность встроенного файла Device CA.
func TestEmbed_DeviceCAPEM_ShouldBeValidPEM(t *testing.T) {
	pemBytes := certs.DeviceCAPEM()
	require.NotEmpty(t, pemBytes, "Встроенный файл device-ca.crt не должен быть пустым")

	block, rest := pem.Decode(pemBytes)
	require.NotNil(t, block, "Байты Device CA должны успешно декодироваться парсером PEM")
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Empty(t, rest)
}
