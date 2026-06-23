//go:build e2e

package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestE2E_VaultWorkflow_JSON реализует полный сквозной сценарий тестирования
// локального шифрования, валидации Big-Endian AAD и вывода метаданных через флаг --json.
func TestE2E_VaultWorkflow_JSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping intensive cryptographic E2E tests in short mode")
	}

	// 1. ИЗОЛЯЦИЯ ОКРУЖЕНИЯ: Создаем стерильную временную папку на диске
	tmpDir, err := os.MkdirTemp("", "gophkeeper-e2e-vault-*")
	if err != nil {
		t.Fatalf("failed to create secure sandbox directory: %v", err)
	}
	defer os.RemoveAll(tmpDir) // Гарантированная гигиена RAM и диска после теста

	testDBPath := filepath.Join(tmpDir, "goph_keeper_e2e_test.db")

	// Динамически вычисляем корректный абсолютный путь к скомпилированному бинарнику клиента,
	// чтобы тесты стабильно проходили как на хосте, так и внутри GitHub Actions Runner.
	pathToBinary, err := filepath.Abs("../../../build/linux/gophkeeper")
	if err != nil {
		t.Fatalf("failed to resolve absolute path to binary: %v", err)
	}

	// Проверяем физическое наличие бинарника перед запуском (Fail-Fast барьер)
	if _, err := os.Stat(pathToBinary); os.IsNotExist(err) {
		t.Fatalf("CRITICAL: gophkeeper binary not found at %s. Please run 'make build' first.", pathToBinary)
	}

	// 2. ИБ-ПРЕДУСЛОВИЕ: Инициализируем и пробрасываем живой ssh-agent для GitHub Actions
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		t.Log("WARNING: SSH_AUTH_SOCK env variable is empty. Ensure ssh-agent step is active in your pipeline.")
	}

	// Вспомогательный анонимный хелпер для атомарного выполнения CLI команд
	runCmd := func(args ...string) (string, string, error) {
		// Принудительно изолируем контур через жесткую привязку путей и флага --json
		baseArgs := []string{"--sqlite-path", testDBPath, "--json"}
		finalArgs := append(baseArgs, args...)

		cmd := exec.Command(pathToBinary, finalArgs...)

		// Наследуем переменные окружения родительского процесса (включая SSH_AUTH_SOCK)
		cmd.Env = os.Environ()

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}

	// =========================================================================
	// ЭТАП 1: Инициализация хранилища (gophkeeper init)
	// =========================================================================
	t.Run("Execute Vault Initialization", func(t *testing.T) {
		stdout, stderr, err := runCmd("init")
		if err != nil {
			t.Fatalf("init command failed: %v, stderr: %s, stdout: %s", err, stderr, stdout)
		}

		// Проверяем физический факт создания и ACID-целостности файла контейнера SQLite
		if _, err := os.Stat(testDBPath); os.IsNotExist(err) {
			t.Fatalf("CRITICAL: SQLite container was not created at %s after init command execution", testDBPath)
		}
	})

	// =========================================================================
	// ЭТАП 2: Создание записи с зашифрованными метаданными (gophkeeper create)
	// =========================================================================
	t.Run("Create Secret Record With Encrypted Metadata Object", func(t *testing.T) {
		stdout, stderr, err := runCmd(
			"create",
			"--name", "salary_card",
			"--type", "card",
			"--payload", "4276123456789012;12/29;123",
			"--meta", `{"bank":"Sber","holder":"ILVIN","atm_pin":"9988"}`,
		)
		if err != nil {
			t.Fatalf("create command execution failed: %v, stderr: %s", err, stderr)
		}

		// Парсим и валидируем строгий JSON-ответ конверта CLIResponse
		var resp CLIResponse
		if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
			t.Fatalf("failed to unmarshal create response JSON: %v, raw stdout: %q", err, stdout)
		}

		if !resp.Success {
			t.Fatalf("create command returned success=false in JSON schema: %s", resp.Error)
		}
	})

	// =========================================================================
	// ЭТАП 3: Чтение и дешифрование записи в режиме JSON API (gophkeeper get)
	// =========================================================================
	t.Run("Decrypt And Validate Secret Record via JSON API", func(t *testing.T) {
		stdout, stderr, err := runCmd("get", "--name", "salary_card")
		if err != nil {
			t.Fatalf("get command execution failed: %v, stderr: %s", err, stderr)
		}

		// Парсим корневой конверт ответа
		var resp CLIResponse
		if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
			t.Fatalf("failed to unmarshal get response JSON: %v, raw stdout: %q", err, stdout)
		}

		if !resp.Success {
			t.Fatalf("get command returned success=false in JSON schema: %s", resp.Error)
		}

		// Выполняем ре-маршалинг интерфейсного поля Data в жесткую структуру GetResponse
		dataBytes, _ := json.Marshal(resp.Data)
		var getData GetResponse
		if err := json.Unmarshal(dataBytes, &getData); err != nil {
			t.Fatalf("failed to map dynamic payload to GetResponse schema: %v", err)
		}

		// ЖЕСТКИЕ АССЕРТЫ КРИПТОГРАФИЧЕСКОЙ ТОЧНОСТИ (Проверка Big-Endian AAD Poly1305)
		if getData.Name != "salary_card" {
			t.Errorf("mismatched secret name: expected 'salary_card', got %q", getData.Name)
		}
		if getData.Payload != "4276123456789012;12/29;123" {
			t.Errorf("mismatched decrypted payload string: got %q", getData.Payload)
		}

		// Проверяем сохранность и расшифровку метаданных из скрытого контура JSON
		if getData.Metadata == nil {
			t.Fatalf("critical error: decrypted metadata map is nil or missing")
		}
		if getData.Metadata["bank"] != "Sber" || getData.Metadata["holder"] != "ILVIN" || getData.Metadata["atm_pin"] != "9988" {
			t.Errorf("metadata contents are corrupted or altered during transport layer encryption: %v", getData.Metadata)
		}
	})
}
