package pki_test

import (
	"testing"

	"gophkeeper/internal/server/config"
	"gophkeeper/internal/server/pki"

	"github.com/stretchr/testify/assert"
)

// TestLoadServerCA_FailsIfPathEmpty проверяет срабатывание Fail-Fast барьера
// валидации при передаче пустой строки пути к ключу Server CA.
func TestLoadServerCA_FailsIfPathEmpty(t *testing.T) {
	cfg := config.Config{}
	cfg.PKI.ServerCAKeyPath = "" // Намеренная пустота

	cert, key, err := pki.LoadServerCA(cfg)

	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "server ca private key path is not configured")
}

// TestLoadDeviceCA_FailsIfPathEmpty проверяет Fail-Fast барьер для Device CA.
func TestLoadDeviceCA_FailsIfPathEmpty(t *testing.T) {
	cfg := config.Config{}
	cfg.PKI.DeviceCAKeyPath = ""

	cert, key, err := pki.LoadDeviceCA(cfg)

	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "device ca private key path is not configured")
}
