package commands

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestSyncResponse_Mapping проверяет корректность DTO-структуры ответа для E2E автоматизации.
func TestSyncResponse_Mapping(t *testing.T) {
	payload := SyncResponse{
		Pulled: 5,
		Pushed: 12,
	}

	assert.Equal(t, 5, payload.Pulled)
	assert.Equal(t, 12, payload.Pushed)
}

// TestSyncCommandFormatting_WithStandardOutput проверяет UX-отображение процесса репликации.
func TestSyncCommandFormatting_WithStandardOutput(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)
	cli.JSONOutput = false

	buf := new(bytes.Buffer)
	mockPayload := SyncResponse{
		Pulled: 3,
		Pushed: 0,
	}

	cli.PrintResult(buf, mockPayload, func() {
		fmt.Fprintf(buf, "  Скачано изменений из облака (Pull): %d\n", mockPayload.Pulled)
		fmt.Fprintf(buf, "  Загружено оффлайн-записей в облако (Push): %d\n", mockPayload.Pushed)
	})

	assert.Contains(t, buf.String(), "Скачано изменений из облака (Pull): 3")
	assert.Contains(t, buf.String(), "Загружено оффлайн-записей в облако (Push): 0")
}
