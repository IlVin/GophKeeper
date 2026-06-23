// Package sshcheck предоставляет инструменты превентивной проверки готовности
// и доступности системного демона ssh-agent до запуска основных крипто-конвейеров.
package sshcheck

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/agent"
)

var (
	// ErrSSHAgentUnavailable возвращается, если системный ssh-agent недоступен или пуст.
	ErrSSHAgentUnavailable = errors.New("ssh agent unavailable")
)

// RequireAgent выполняет fail-fast проверку доступности UNIX-сокета ssh-agent.
//
// Функция верифицирует переменную SSH_AUTH_SOCK, открывает тестовое соединение
// и контролирует наличие хотя бы одного загруженного ключа (Инвариант №4).
func RequireAgent() error {
	slog.Debug("Executing pre-flight validation check for active system ssh-agent")

	sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if sock == "" {
		slog.Warn("Pre-flight check rejected: SSH_AUTH_SOCK environment variable is not set")
		return fmt.Errorf("%w: SSH_AUTH_SOCK environment variable is not set", ErrSSHAgentUnavailable)
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		slog.Error("Failed to dial unix socket path specified in SSH_AUTH_SOCK", "path", sock, "error", err)
		return fmt.Errorf("%w: cannot connect to SSH_AUTH_SOCK socket %q: %v", ErrSSHAgentUnavailable, sock, err)
	}

	connClosed := false
	defer func() {
		if !connClosed {
			if closeErr := conn.Close(); closeErr != nil {
				slog.Error("Failed to close diagnostic ssh-agent net connection descriptor", "error", closeErr)
			}
		}
	}()

	agentClient := agent.NewClient(conn)

	// ИСПРАВЛЕНО: Вместо уязвимого Signers() вызываем List() для безопасного извлечения ключей
	keys, err := agentClient.List()
	if err != nil {
		slog.Error("System ssh-agent daemon rejected keys list request or socket is broken", "error", err)
		return fmt.Errorf("%w: ssh-agent socket is not responding correctly: %v", ErrSSHAgentUnavailable, err)
	}

	if len(keys) == 0 {
		slog.Warn("Pre-flight check rejected: ssh-agent is running but contains zero loaded keys")
		return fmt.Errorf("%w: no SSH keys loaded in ssh-agent, vault cannot be unlocked", ErrSSHAgentUnavailable)
	}

	slog.Debug("Pre-flight ssh-agent verification check completed successfully", "loaded_keys_count", len(keys))

	// Безопасно финализируем дескриптор до выхода
	if closeErr := conn.Close(); closeErr != nil {
		slog.Error("Failed to close active diagnostic socket descriptor on success path", "error", closeErr)
	}
	connClosed = true

	return nil
}

// FormatSSHAgentHelp возвращает подробную англоязычную инструкцию для пользователя
// по запуску и наполнению ключами демона ssh-agent в операционной системе.
func FormatSSHAgentHelp() string {
	return `GophKeeper requires a working ssh-agent for this command.

Recovery steps:
  1. Generate an SSH key if you do not have one:
     ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519

  2. Start ssh-agent daemon in your shell:
     eval "$(ssh-agent -s)"

  3. Add your private key to the running agent:
     ssh-add ~/.ssh/id_ed25519

  4. Verify loaded keys via 'ssh-add -l' and retry the command.`
}
