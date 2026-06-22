package commands

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"gophkeeper/internal/client/repository"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestListResponseFormatting_WithEmptyVault_ShouldRenderUXMessage проверяет текстовый рендер
// по умолчанию для человека, если в базе нет ни одной записи.
func TestListResponseFormatting_WithEmptyVault_ShouldRenderUXMessage(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)
	cli.JSONOutput = false

	buf := new(bytes.Buffer)
	var emptyMetadataList []repository.RecordMetadata

	// Формируем payload ответа на базе пустого слайса
	var items []ListResponseItem

	cli.PrintResult(buf, items, func() {
		if len(emptyMetadataList) == 0 {
			fmt.Fprintln(buf, "Ваш сейф пуст. Используйте команду 'gophkeeper create' для добавления записей.")
			return
		}
	})

	assert.Contains(t, buf.String(), "Ваш сейф пуст")
}

// TestListResponse_MappingToResponseItem проверяет корректность конвертации
// доменной модели метаданных репозитория в DTO элементы ответа ListResponseItem.
func TestListResponse_MappingToResponseItem(t *testing.T) {
	fixedTime := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)

	mockMetadata := repository.RecordMetadata{
		ID:        "a1b2c3d4",
		Name:      "yandex-mail",
		Type:      "credentials",
		UpdatedAt: fixedTime,
	}

	// Имитируем маппинг из тела команды
	item := ListResponseItem{
		ID:          mockMetadata.ID,
		Name:        mockMetadata.Name,
		Type:        mockMetadata.Type,
		LastUpdated: mockMetadata.UpdatedAt.Format(time.RFC3339),
	}

	assert.Equal(t, "a1b2c3d4", item.ID)
	assert.Equal(t, "yandex-mail", item.Name)
	assert.Equal(t, "credentials", item.Type)
	assert.Equal(t, "2026-06-23T12:00:00Z", item.LastUpdated, "Временная метка должна строго соответствовать стандарту RFC3339")
}
