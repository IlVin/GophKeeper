package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetResponse_Destroy_ShouldClearMetadata проверяет корректность функционирования
// деструктора GetResponse, контролируя полное вычищение элементов из карты метаданных.
func TestGetResponse_Destroy_ShouldClearMetadata(t *testing.T) {
	mockMeta := map[string]string{
		"token-type": "bearer",
		"scope":      "write",
	}

	resp := &GetResponse{
		Name:     "github-oauth",
		Payload:  "ghp_secret_token_data_12345",
		Metadata: mockMeta,
	}

	// Проверяем исходное состояние до очистки
	assert.Len(t, resp.Metadata, 2)
	assert.Equal(t, "ghp_secret_token_data_12345", resp.Payload)

	// Вызываем зануление DTO
	resp.Destroy()

	// Проверяем финальное состояние ИБ-гигиены
	assert.Empty(t, resp.Payload, "Payload string field should be cleared")
	assert.Len(t, resp.Metadata, 0, "All metadata map elements should be permanently removed")
}

// TestGetResponse_DestroyWithNil_ShouldNotPanic проверяет устойчивость
// деструктора к передаче пустой ссылки (nil pointer protection).
func TestGetResponse_DestroyWithNil_ShouldNotPanic(t *testing.T) {
	var resp *GetResponse = nil

	// Call on nil object should not cause runtime panic
	assert.NotPanics(t, func() {
		resp.Destroy()
	})
}
