package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRun_WithHelpFlag_ShouldSuccess(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Имитируем вызов клиента с флагом --help, чтобы проверить дерево команд без инициализации базы и сокетов
	os.Args = []string{"gophkeeper", "--help"}

	err := run()
	assert.NoError(t, err, "Executing client with --help flag must not return an error")
}

func TestRun_WithInvalidFlag_ShouldReturnError(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Передаем неизвестный флаг для проверки обработки ошибок парсинга в Cobra
	os.Args = []string{"gophkeeper", "--invalid-unknown-client-flag"}

	err := run()
	assert.Error(t, err, "Executing client with unknown flags must return an execution error")
}
