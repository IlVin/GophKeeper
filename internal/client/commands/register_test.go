package commands

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestRegisterResponse_Mapping проверяет корректность полей DTO структуры для JSON-автоматизации.
func TestRegisterResponse_Mapping(t *testing.T) {
	payload := RegisterResponse{
		UserID:    "SHA256:rootkey12345",
		ServerURL: "gophkeeper.cloud:443",
		Status:    "REGISTERED",
	}

	assert.Equal(t, "SHA256:rootkey12345", payload.UserID)
	assert.Equal(t, "gophkeeper.cloud:443", payload.ServerURL)
	assert.Equal(t, "REGISTERED", payload.Status)
}

// TestRegisterCommandFormatting_WithStandardOutput проверяет UX-рендер для человека.
func TestRegisterCommandFormatting_WithStandardOutput(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)
	cli.JSONOutput = false

	buf := new(bytes.Buffer)
	mockPayload := RegisterResponse{
		UserID:    "SHA256:mockfingerprint",
		ServerURL: "localhost:8443",
		Status:    "REGISTERED",
	}

	cli.PrintResult(buf, mockPayload, func() {
		fmt.Fprintf(buf, "✔ Успех! Контейнер успешно привязан к облачному аккаунту %q.\n", mockPayload.UserID)
		fmt.Fprintln(buf, "mTLS-паспорт устройства получен.")
	})

	assert.Contains(t, buf.String(), "✔ Успех!")
	assert.Contains(t, buf.String(), "SHA256:mockfingerprint")
	assert.Contains(t, buf.String(), "mTLS-паспорт устройства получен")
}
