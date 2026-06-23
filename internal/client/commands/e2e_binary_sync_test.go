//go:build e2e

package commands

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestE2E_BinaryPayloadSyncAndVerification генерирует файл размером 9 МБ с рандомным содержимым,
// запечатывает его в локальном сейфе, реплицирует в облако и проверяет побайтовую идентичность
// расшифрованного файла на изолированной второй копии клиента.
func TestE2E_BinaryPayloadSyncAndVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping intensive large binary sync E2E tests in short mode")
	}

	// 1. ИЗОЛЯЦИЯ ОКРУЖЕНИЯ: Создаем песочницу для двух клиентов и временных файлов
	tmpDir, err := os.MkdirTemp("", "gophkeeper-e2e-binary-*")
	if err != nil {
		t.Fatalf("failed to create secure sandbox directory: %v", err)
	}
	defer os.RemoveAll(tmpDir) // Гарантированная зачистка диска после теста

	dbClient1 := filepath.Join(tmpDir, "vault_source.db")
	dbClient2 := filepath.Join(tmpDir, "vault_replica.db")
	sourceFilePath := filepath.Join(tmpDir, "source_9mb.bin")

	// Находим абсолютные пути к скомпилированным кроссплатформенным бинарникам
	clientBinary, _ := filepath.Abs("../../../build/linux/gophkeeper")
	serverBinary, _ := filepath.Abs("../../../build/linux/gophkeeper-server")

	// Проверяем физическое наличие артефактов компиляции (Fail-Fast)
	if _, err := os.Stat(clientBinary); os.IsNotExist(err) {
		t.Fatalf("client binary not found at %q. Run 'make build-linux' first", clientBinary)
	}
	if _, err := os.Stat(serverBinary); os.IsNotExist(err) {
		t.Fatalf("server binary not found at %q. Run 'make build-linux' first", serverBinary)
	}

	// 2. ГЕНЕРАЦИЯ БОЛЬШОГО ВЫСОКОЭНТРОПИЙНОГО ФАЙЛА (9 Мегабайт)
	t.Log("Generating 9 Megabytes highly-entropic random binary file...")
	const binarySize9MB = 9 * 1024 * 1024
	randomBytes := make([]byte, binarySize9MB)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		t.Fatalf("failed to generate system entropy stream: %v", err)
	}

	if err := os.WriteFile(sourceFilePath, randomBytes, 0o600); err != nil {
		t.Fatalf("failed to persist 9MB source file to scratch disk: %v", err)
	}

	// 3. ИНФРАСТРУКТУРНЫЙ SPIN-UP ОБЛАЧНОГО СЕРВЕРА
	serverTargetAddr := "127.0.0.1:9554"
	postgresDSN := os.Getenv("DATABASE_DSN")
	if postgresDSN == "" {
		postgresDSN = "postgres://gophkeeper:gophkeeper_pswd@127.0.0.1:5432/gophkeeper?sslmode=disable"
	}

	serverCAKeyAbs, _ := filepath.Abs("../../../.certs_private/server-ca.key")
	deviceCAKeyAbs, _ := filepath.Abs("../../../.certs_private/device-ca.key")

	serverCmd := exec.Command(serverBinary, "start",
		"--bind-grpc", serverTargetAddr,
		"--database", postgresDSN,
		"--server-ca-key", serverCAKeyAbs,
		"--device-ca-key", deviceCAKeyAbs,
	)
	serverCmd.Env = os.Environ()

	var serverStderr bytes.Buffer
	serverCmd.Stderr = &serverStderr

	if err := serverCmd.Start(); err != nil {
		t.Fatalf("failed to boot infrastructure gRPC server: %v", err)
	}
	defer func() {
		if serverCmd.Process != nil {
			_ = serverCmd.Process.Kill()
		}
	}()

	// Даем gRPC-серверу время на запуск сетевого стека и пинг PostgreSQL
	time.Sleep(600 * time.Millisecond)

	// Утилитарный хелпер для выполнения CLI-команд изолированных клиентов
	runClient := func(dbPath string, args ...string) (string, string, error) {
		baseArgs := []string{"--sqlite-path", dbPath, "--json"}
		finalArgs := append(baseArgs, args...)

		cmd := exec.Command(clientBinary, finalArgs...)
		cmd.Env = os.Environ() // Пробрасываем SSH_AUTH_SOCK для доступа к ssh-agent

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}

	// =========================================================================
	// ЭТАП 1: ИНИЦИАЛИЗАЦИЯ И mTLS АНКОРИНГ КЛИЕНТОВ
	// =========================================================================
	t.Run("Initialize and Link Two Independent Vaults", func(t *testing.T) {
		dbs := []string{dbClient1, dbClient2}
		for i, db := range dbs {
			if _, _, err := runClient(db, "init"); err != nil {
				t.Fatalf("client_%d local init failed: %v", i+1, err)
			}
			stdout, stderr, err := runClient(db, "register", "--server", serverTargetAddr)
			if err != nil {
				t.Fatalf("client_%d cloud registration failed: %v, stderr: %s", i+1, err, stderr)
			}

			var resp CLIResponse
			_ = json.Unmarshal([]byte(stdout), &resp)
			if !resp.Success {
				t.Fatalf("server rejected client_%d registration: %s", i+1, resp.Error)
			}
		}
	})

	// =========================================================================
	// ЭТАП 2: ЗАПЕЧАТЫВАНИЕ БИНАРНОГО КОНВЕРТА НА КЛИЕНТЕ 1
	// =========================================================================
	t.Run("Seal 9MB Binary Blob Into Source Vault", func(t *testing.T) {
		stdout, stderr, err := runClient(dbClient1,
			"create",
			"--name", "large_backup.bin",
			"--type", "binary",
			"--file", sourceFilePath,
			"--meta", `{"version":"v1.0.0","env":"production"}`,
		)
		if err != nil {
			t.Fatalf("failed to execute create command for binary data: %v, stderr: %s", err, stderr)
		}

		var resp CLIResponse
		_ = json.Unmarshal([]byte(stdout), &resp)
		if !resp.Success {
			t.Fatalf("create command returned success=false inside JSON: %s", resp.Error)
		}
	})

	// =========================================================================
	// ЭТАП 3: РЕПЛИКАЦИЯ В ОБЛАКО И ДИФФЕРЕНЦИАЛЬНЫЙ PULL НА КЛИЕНТЕ 2
	// =========================================================================
	t.Run("Replicate Opaque Ciphertext and Pull onto Replica Client", func(t *testing.T) {
		// Клиент 1: Пушит 9МБ зашифрованный конверт в Postgres
		stdout1, stderr1, err := runClient(dbClient1, "sync")
		if err != nil {
			t.Fatalf("client_1 sync failed: %v, stderr: %s", err, stderr1)
		}
		var resp1 CLIResponse
		_ = json.Unmarshal([]byte(stdout1), &resp1)
		if !resp1.Success {
			t.Fatalf("client_1 sync returned error: %s", resp1.Error)
		}

		// Клиент 2: Выкачивает изменения по mTLS каналу по стратегии LWW
		stdout2, stderr2, err := runClient(dbClient2, "sync")
		if err != nil {
			t.Fatalf("client_2 sync failed: %v, stderr: %s", err, stderr2)
		}
		var resp2 CLIResponse
		_ = json.Unmarshal([]byte(stdout2), &resp2)
		if !resp2.Success {
			t.Fatalf("client_2 sync returned error: %s", resp2.Error)
		}
	})

	// =========================================================================
	// ЭТАП 4: ДЕШИФРОВАНИЕ И ПОБАЙТОВАЯ ВЕРИФИКАЦИЯ ЦЕЛОСТНОСТИ ЦЕПОЧКИ
	// =========================================================================
	t.Run("Decrypt Sealed Envelope on Replica Client and Assert Integrity", func(t *testing.T) {
		stdout, stderr, err := runClient(dbClient2, "get", "--name", "large_backup.bin")
		if err != nil {
			t.Fatalf("failed to fetch and decrypt record on replica client: %v, stderr: %s", err, stderr)
		}

		var resp CLIResponse
		if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
			t.Fatalf("failed to decode json response envelope: %v, raw stdout: %q", err, stdout)
		}

		if !resp.Success {
			t.Fatalf("get command failed inside json token: %s", resp.Error)
		}

		// Преобразуем динамическое поле Data в DTO GetResponse
		dataBytes, _ := json.Marshal(resp.Data)
		var getData GetResponse
		_ = json.Unmarshal(dataBytes, &getData)

		// Извлекаем дешифрованные байты полезной нагрузки (Payload)
		decryptedPayloadBytes := []byte(getData.Payload)

		// ВЕРИФИКАЦИЯ ИБ-ИНВАРИАНТА: Размер и байты должны совпасть абсолютно
		if len(decryptedPayloadBytes) != binarySize9MB {
			t.Errorf("integrity violation: expected decrypted file size to be %d bytes, but got %d",
				binarySize9MB, len(decryptedPayloadBytes))
		}

		slog.Info("Executing memory-to-memory bitwise comparison of decrypted stream versus original entropy")
		if !bytes.Equal(randomBytes, decryptedPayloadBytes) {
			t.Error("CRITICAL SECURITY DEFECT: Decrypted binary file content is corrupted or altered. Bitwise mismatch found!")
		} else {
			t.Log("✔ Success! Decrypted 9MB binary payload is bitwise identical to the source file.")
		}

		// Валидируем сопутствующие зашифрованные метаданные конверта
		if getData.Metadata["bank"] != "" { // Проверка, что чужие метаданные не попали
			t.Errorf("unexpected metadata found inside decrypted scope")
		}
		if getData.Metadata["env"] != "production" || getData.Metadata["version"] != "v1.0.0" {
			t.Errorf("record metadata mapping is broken or corrupted: %v", getData.Metadata)
		}
	})
}
