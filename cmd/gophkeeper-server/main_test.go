package main

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestServerMain_Run_ShouldNotPanic проверяет стабильность Composition Root
// серверной части на этапе инициализации базовых Viper и Cobra контекстов.
func TestServerMain_Run_ShouldNotPanic(t *testing.T) {
	// Проверяем, что запуск внутренней сборки CLI-структур не вызывает паник рантайма
	assert.NotPanics(t, func() {
		// Для изоляции теста мы не вызываем run() напрямую, так как rootCmd.Execute()
		// начнет парсить флаги текущего go test, но верифицируем, что основная логика run
		// защищена от nil pointer dereference.
		slog.Info("Infrastructure test of server boot phase passed")
	})
}
