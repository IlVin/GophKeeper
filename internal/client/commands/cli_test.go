package commands

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewCLI_ShouldSetInternalViper проверяет фабрику и привязку движка конфигурации.
func TestNewCLI_ShouldSetInternalViper(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)

	assert.NotNil(t, cli)
	assert.Equal(t, v, cli.Viper(), "Viper() should return the original pointer")
}

// TestPrintResult_WithJSONOutput_ShouldFormatCorrectEnvelope проверяет
// работу подсистемы вывода результатов в режиме автоматизации (--json).
func TestPrintResult_WithJSONOutput_ShouldFormatCorrectEnvelope(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)
	cli.JSONOutput = true // Включаем режим автоматизации

	buf := new(bytes.Buffer)
	payload := map[string]string{"status": "OK"}

	cli.PrintResult(buf, payload, func() {
		t.Fatal("Custom text render should not be called in JSON mode")
	})

	expectedJSON := `{"success":true,"data":{"status":"OK"}}` + "\n"
	assert.Equal(t, expectedJSON, buf.String(), "Output should be wrapped in canonical JSON envelope")
}

// TestPrintError_WithJSONOutput_ShouldSuppressCobraError проверяет, что в режиме
// автоматизации ошибка заворачивается в конверт, а сам метод возвращает nil для гашения stderr.
func TestPrintError_WithJSONOutput_ShouldSuppressCobraError(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)
	cli.JSONOutput = true

	buf := new(bytes.Buffer)
	targetErr := errors.New("network failure")

	err := cli.PrintError(buf, targetErr, "failed to sync")

	assert.NoError(t, err, "Method should return nil so Cobra doesn.t duplicate error to stderr")

	expectedJSON := `{"success":false,"error":"failed to sync: network failure"}` + "\n"
	assert.Equal(t, expectedJSON, buf.String(), "Error text should be properly wrapped in JSON envelope")
}

// TestPrintError_WithStandardOutput_ShouldReturnWrappedError проверяет поведение
// по умолчанию для человека (ошибка пробрасывается наверх без записи в поток вывода).
func TestPrintError_WithStandardOutput_ShouldReturnWrappedError(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)
	cli.JSONOutput = false

	buf := new(bytes.Buffer)
	targetErr := errors.New("disk is full")

	err := cli.PrintError(buf, targetErr, "failed to save")

	require.Error(t, err, "In standard mode error should be propagated upward")
	assert.Contains(t, err.Error(), "failed to save: disk is full")
	assert.Empty(t, buf.String(), "Output stream should remain clean")
}
