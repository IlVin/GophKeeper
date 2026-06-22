package commands

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestDeleteResultPayload_Mapping проверяет корректность структуры DTO-ответа для сериализации JSON.
func TestDeleteResultPayload_Mapping(t *testing.T) {
	payload := DeleteResultPayload{
		ID:     "test-uuid-12345",
		Status: "DELETED",
	}

	assert.Equal(t, "test-uuid-12345", payload.ID)
	assert.Equal(t, "DELETED", payload.Status)
}

// TestDeleteCommandFormatting_WithStandardOutput проверяет псевдографический рендер успешного удаления.
func TestDeleteCommandFormatting_WithStandardOutput(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)
	cli.JSONOutput = false

	buf := new(bytes.Buffer)
	mockPayload := DeleteResultPayload{
		ID:     "a1b2c3d4",
		Status: "DELETED",
	}

	cli.PrintResult(buf, mockPayload, func() {
		fmt.Fprintf(buf, "✔ Успех! Запись %q (ID: %s) была безвозвратно удалена.\n", "yandex-token", mockPayload.ID)
	})

	assert.Contains(t, buf.String(), "✔ Успех!")
	assert.Contains(t, buf.String(), "yandex-token")
	assert.Contains(t, buf.String(), "ID: a1b2c3d4")
}
