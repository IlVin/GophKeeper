package sshcheck_test

import (
	"os"
	"testing"

	"gophkeeper/internal/client/sshcheck"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequireAgent_WhenEnvMissing_ShouldReturnError_And_HelpVerify проверяет,
// что метод пресекает запуск, если переменная окружения SSH_AUTH_SOCK удалена из ОС.
func TestRequireAgent_WhenEnvMissing_ShouldReturnError_And_HelpVerify(t *testing.T) {
	// Сохраняем оригинальное состояние окружения ОС
	origSock := os.Getenv("SSH_AUTH_SOCK")
	err := os.Setenv("SSH_AUTH_SOCK", "")
	require.NoError(t, err)

	// Гарантируем восстановление окружения после теста
	defer func() {
		_ = os.Setenv("SSH_AUTH_SOCK", origSock)
	}()

	err = sshcheck.RequireAgent()
	assert.ErrorIs(t, err, sshcheck.ErrSSHAgentUnavailable, "Function must return agent unavailable error")
	assert.Contains(t, err.Error(), "SSH_AUTH_SOCK environment variable is not set", "Error text must be in English")

	// Проверяем формат возвращаемой справки спасения
	helpText := sshcheck.FormatSSHAgentHelp()
	assert.Contains(t, helpText, "ssh-keygen -t ed25519")
	assert.Contains(t, helpText, "ssh-add")
}
