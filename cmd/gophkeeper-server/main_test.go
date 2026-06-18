package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRun_WithHelpFlag_ShouldSuccess(t *testing.T) {
	// Сохраняем оригинальные аргументы командной строки
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Подменяем аргументы: имитируем вызов сервера с флагом --help
	// Это проверяет инициализацию Viper, парсинг флагов и сборку дерева команд,
	// но не запускает сетевые сокеты и базу данных.
	os.Args = []string{"gophkeeper-server", "--help"}

	// Выполняем логику запуска
	err := run()

	// Проверяем инвариант: сборка и парсинг справки должны пройти без ошибок
	assert.NoError(t, err, "Executing server with --help flag must not return an error")
}

func TestRun_WithInvalidFlag_ShouldReturnError(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Передаем несуществующий флаг, чтобы спровоцировать ошибку парсинга Cobra
	os.Args = []string{"gophkeeper-server", "--invalid-unknown-flag"}

	err := run()

	// Проверяем инвариант: Cobra должна вернуть ошибку парсинга аргументов
	assert.Error(t, err, "Executing server with unknown flags must return an execution error")
}
