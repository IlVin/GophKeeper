package commands_test

import (
	"testing"

	"gophkeeper/internal/server/commands"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestServerCLI_Close_ShouldNotPanic проверяет отказоустойчивость деструктора
// управляющего контекста при вызове на неинициализированной фабрике.
func TestServerCLI_Close_ShouldNotPanic(t *testing.T) {
	emptyViper := viper.New()
	serverCLI := commands.NewServerCLI(emptyViper)

	// Вызов Close() до вызова App() должен чисто вернуть nil без паник разыменования указателей
	assert.NotPanics(t, func() {
		err := serverCLI.Close()
		assert.NoError(t, err)
	}, "Деструктор контекста обязан безопасно обрабатывать пустые рантайм-модели")
}

// TestServerCLI_Constructor_Success проверяет сборку фабрики.
func TestServerCLI_Constructor_Success(t *testing.T) {
	emptyViper := viper.New()
	serverCLI := commands.NewServerCLI(emptyViper)
	assert.NotNil(t, serverCLI)
}
