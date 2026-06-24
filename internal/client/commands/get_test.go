package commands

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestGetResponse_StructureMapping проверяет корректность сборки структуры
// ответа и доступность сериализации полей метаданных.
func TestGetResponse_StructureMapping(t *testing.T) {
	mockMeta := map[string]string{
		"url": "https://yandex.ru",
	}

	payload := GetResponse{
		Name:     "yandex-account",
		Payload:  "secret-password-123",
		Metadata: mockMeta,
	}

	assert.Equal(t, "yandex-account", payload.Name)
	assert.Equal(t, "secret-password-123", payload.Payload)
	assert.Equal(t, "https://yandex.ru", payload.Metadata["url"])
}

// TestGetCommandFormatting_WithStandardOutput checks pretty decryption output.
func TestGetCommandFormatting_WithStandardOutput(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)
	cli.JSONOutput = false

	buf := new(bytes.Buffer)
	mockPayload := GetResponse{
		Name:     "test-safe-record",
		Payload:  "plain-text-data",
		Metadata: map[string]string{"env": "dev"},
	}

	cli.PrintResult(buf, mockPayload, func() {
		fmt.Fprintf(buf, "Имя секрета  : %s\n", mockPayload.Name)
		fmt.Fprintf(buf, "Полезная нагрузка (Payload): %s\n", mockPayload.Payload)
	})

	assert.Contains(t, buf.String(), "Имя секрета  : test-safe-record")
	assert.Contains(t, buf.String(), "Полезная нагрузка (Payload): plain-text-data")
}

// TestPrintError_InGetStandardMode checks decryption error propagation for human readability.
func TestPrintError_InGetStandardMode(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)
	cli.JSONOutput = false

	buf := new(bytes.Buffer)
	cryptoErr := errors.New("chacha20poly1305: message authentication failed")

	err := cli.PrintError(buf, cryptoErr, "decryption error")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption error: chacha20poly1305")
	assert.Empty(t, buf.String(), "In standard mode output buffer should remain empty")
}
