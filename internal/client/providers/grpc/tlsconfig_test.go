package grpc_test

import (
	"crypto/tls"
	"testing"

	"gophkeeper/internal/client/providers/grpc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ConfigForTest возвращает тестовую конфигурацию TLS.
// Согласно ИБ-стандартам, метод вынесен из основного кода прямо в тестовый файл.
func ConfigForTest() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS13,
	}
}

// TestConfigForBootstrap_ShouldEnforceTLS13 проверяет, что bootstrap-конфигурация
// успешно собирается и намертво блокирует версии ниже TLS 1.3.
func TestConfigForBootstrap_ShouldEnforceTLS13(t *testing.T) {
	cfg, err := grpc.ConfigForBootstrap()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion, "Transport must strictly require TLS 1.3 version")
	assert.NotNil(t, cfg.RootCAs, "Trusted Server CA pool must be initialized")
	assert.Nil(t, cfg.Certificates, "Client certificate must be absent at bootstrap phase")
}

// TestConfigForMTLS_WithEmptyCert_ShouldReturnError проверяет срабатывание fail-fast
// барьера, если в конфигуратор mTLS передан пустой контейнер сертификата.
func TestConfigForMTLS_WithEmptyCert_ShouldReturnError(t *testing.T) {
	emptyCert := tls.Certificate{}

	cfg, err := grpc.ConfigForMTLS(emptyCert, nil)
	assert.ErrorIs(t, err, grpc.ErrEmptyCertificate)
	assert.Nil(t, cfg)
}

// TestConfigForMTLS_Success проверяет корректность сборки двустороннего mTLS-контекста.
func TestConfigForMTLS_Success(t *testing.T) {
	// Создаем фиктивный непустой сертификат для прохождения валидации
	dummyCert := tls.Certificate{
		Certificate: [][]byte{{0x01, 0x02}},
	}

	cfg, err := grpc.ConfigForMTLS(dummyCert, nil)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.Len(t, cfg.Certificates, 1, "Context must contain exactly one client mTLS passport")
	assert.Equal(t, dummyCert.Certificate[0], cfg.Certificates[0].Certificate[0])
}

// TestConfigForTest_Verification проверяет параметры изолированного тестового конфигуратора.
func TestConfigForTest_Verification(t *testing.T) {
	cfg := ConfigForTest()
	assert.True(t, cfg.InsecureSkipVerify)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
}
