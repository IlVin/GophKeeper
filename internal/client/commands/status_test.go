package commands

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewStatusCommand_Flags(t *testing.T) {
	t.Parallel()

	cmd := newStatusCommand()
	assert.Equal(t, "status", cmd.Use)
	assert.NotNil(t, cmd.Flags().Lookup("server"))
}

func TestNewStatusCommand_ExecutionFailClosedOnConnection(t *testing.T) {
	t.Parallel()

	cmd := newStatusCommand()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetContext(context.Background())

	// Бьем на несуществующий или невалидный локальный адрес, ожидаем падение (fail closed)
	cmd.SetArgs([]string{"--server", "127.0.0.1:9999"})
	err := cmd.Execute()

	// Должна вернуться ошибка сетевого подключения/сертификата
	assert.Error(t, err)
}
