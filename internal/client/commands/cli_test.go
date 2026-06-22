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
	assert.Equal(t, v, cli.Viper(), "Метод Viper() должен возвращать исходный указатель")
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
		t.Fatal("Пользовательский текстовый рендер не должен вызываться в режиме JSON")
	})

	expectedJSON := `{"success":true,"data":{"status":"OK"}}` + "\n"
	assert.Equal(t, expectedJSON, buf.String(), "Вывод должен быть упакован в каноничный JSON-конверт")
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

	assert.NoError(t, err, "Метод должен вернуть nil, чтобы Cobra не дублировала ошибку в системный stderr")

	expectedJSON := `{"success":false,"error":"failed to sync: network failure"}` + "\n"
	assert.Equal(t, expectedJSON, buf.String(), "Текст ошибки должен быть корректно обернут в JSON-конверт")
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

	require.Error(t, err, "В стандартном режиме ошибка должна пробрасываться наверх")
	assert.Contains(t, err.Error(), "failed to save: disk is full")
	assert.Empty(t, buf.String(), "Поток вывода должен оставаться чистым")
}
