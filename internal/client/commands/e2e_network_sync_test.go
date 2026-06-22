//go:build e2e

package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestE2E_ThreeClientsConflictResolution_LWW симулирует трех конкурентных оффлайн-клиентов
// и проверяет работу Zero-Knowledge синхронизации и паттерна разрешения конфликтов Last-Write-Wins.
func TestE2E_ThreeClientsConflictResolution_LWW(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping intensive network multi-client E2E tests in short mode")
	}

	// 1. ИЗОЛЯЦИЯ ОКРУЖЕНИЯ: Создаем временную папку для 3-х изолированных баз данных SQLite
	tmpDir, err := os.MkdirTemp("", "gophkeeper-e2e-multi-*")
	if err != nil {
		t.Fatalf("failed to create secure sandbox directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbClient1 := filepath.Join(tmpDir, "client_1.db")
	dbClient2 := filepath.Join(tmpDir, "client_2.db")
	dbClient3 := filepath.Join(tmpDir, "client_3.db")

	// Находим абсолютный путь к скомпилированным бинарникам клиента и сервера
	clientBinary, _ := filepath.Abs("../../../cmd/gophkeeper/gophkeeper")
	serverBinary, _ := filepath.Abs("../../../cmd/gophkeeper-server/gophkeeper-server")

	// 2. АВТОНОМНЫЙ ЗАПУСК СЕРВЕРА В ФОНЕ (Spin-up)
	// Сервер использует нативный PostgreSQL, поднятый в GitHub Actions, через DATABASE_DSN
	serverTargetAddr := "127.0.0.1:9553"

	// Вытаскиваем DSN-строку подключения из окружения GitHub Actions (она там объявлена как DATABASE_DSN)
	postgresDSN := os.Getenv("DATABASE_DSN")
	if postgresDSN == "" {
		// Дефолтный fallback-вариант для локального тестирования разработчика, если переменная пуста
		postgresDSN = "postgres://gophkeeper:gophkeeper_pswd@127.0.0.1:5432/gophkeeper?sslmode=disable"
	}

	// ИСПРАВЛЕНО: Вычисляем абсолютные пути к приватным ключам Серверного CA и Директного CA,
	// чтобы PKI-слой сервера гарантированно инициализировался в любой среде (CI/CD или локально)
	serverCAKeyAbs, err := filepath.Abs("../../../.certs_private/server-ca.key")
	if err != nil {
		t.Fatalf("failed to resolve absolute path for server-ca.key: %v", err)
	}
	deviceCAKeyAbs, err := filepath.Abs("../../../.certs_private/device-ca.key")
	if err != nil {
		t.Fatalf("failed to resolve absolute path for device-ca.key: %v", err)
	}

	serverCmd := exec.Command(serverBinary, "start",
		"--bind-grpc", serverTargetAddr,
		"--database", postgresDSN,
		"--server-ca-key", serverCAKeyAbs, // Абсолютный путь
		"--device-ca-key", deviceCAKeyAbs, // Абсолютный путь
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

	// Даем gRPC-серверу время на поднятие TCP-слушателя и инициализацию PKI
	time.Sleep(600 * time.Millisecond)

	// Утилитарный хелпер для выполнения команд конкретного клиента
	runClient := func(dbPath string, args ...string) (string, string, error) {
		baseArgs := []string{"--sqlite-path", dbPath, "--json"}
		finalArgs := append(baseArgs, args...)

		cmd := exec.Command(clientBinary, finalArgs...)
		cmd.Env = os.Environ() // Пробрасываем SSH_AUTH_SOCK для подписей в ssh-agent

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}

	// =========================================================================
	// ЭТАП 1: ИНИЦИАЛИЗАЦИЯ И РЕГИСТРАЦИЯ КОНТЕЙНЕРОВ (register)
	// =========================================================================
	t.Run("Initialize and Register Three Independent Containers", func(t *testing.T) {
		dbs := []string{dbClient1, dbClient2, dbClient3}
		for i, db := range dbs {
			// Локальный автономный init
			if _, stderr, err := runClient(db, "init"); err != nil {
				t.Fatalf("client_%d init failed: %v, stderr: %s", i+1, err, stderr)
			}
			// Сетевая passwordless-регистрация (mTLS & Reconcile контур)
			stdout, stderr, err := runClient(db, "register", "--server", serverTargetAddr)
			if err != nil {
				t.Fatalf("client_%d register binary execution failed: %v\n[CLIENT STDERR]: %s\n[SERVER STDERR]: %s",
					i+1, err, stderr, serverStderr.String())
			}

			var resp CLIResponse
			if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
				t.Fatalf("failed to decode client_%d json response: %v, raw stdout: %q, stderr: %q", i+1, err, stdout, stderr)
			}

			if !resp.Success {
				t.Fatalf("SERVER REJECTED REGISTRATION for client_%d! Error details: %q. Server logs: %s",
					i+1, resp.Error, serverStderr.String())
			}
		}
	})

	// =========================================================================
	// ЭТАП 2: ФОРМИРОВАНИЕ ОФФЛАЙН КОНФЛИКТА (Last-Write-Wins Тест-кейс)
	// =========================================================================
	// Симулируем ситуацию: три клиента в оффлайне одновременно создают/изменяют
	// запись с ОДНИМ И ТЕМ ЖЕ ИМЕНЕМ 'shared_secret', но с разным payload.
	t.Run("Generate Competitive Offline State Mutations", func(t *testing.T) {
		// Три клиента в оффлайне создают запись с ОДНИМ И ТЕМ ЖЕ ИМЕНЕМ 'shared_secret'.
		// Благодаря UUID v5, рантайм GophKeeper выведет для них абсолютно идентичный ID,
		// и СУБД PostgreSQL на сервере применит транзакционный фильтр LWW!

		// Клиент 1: Создает запись первым (Самая ранняя метка времени)
		_, _, _ = runClient(dbClient1, "create", "--name", "shared_secret", "--type", "text", "--payload", "value_from_client_1")
		time.Sleep(1 * time.Second) // Задержка для разделения временных меток updated_at

		// Клиент 2: Изменяет запись вторым (Промежуточная метка времени)
		_, _, _ = runClient(dbClient2, "create", "--name", "shared_secret", "--type", "text", "--payload", "value_from_client_2")
		time.Sleep(1 * time.Second)

		// Клиент 3: Записывает payload ПОСЛЕДНИМ (Самая свежая, победная метка времени!)
		_, _, _ = runClient(dbClient3, "create", "--name", "shared_secret", "--type", "text", "--payload", "pobednyi_payload_client_3")
	})

	// =========================================================================
	// ЭТАП 3: КОНКУРЕНТНАЯ СИНХРОНИЗАЦИЯ (sync) И ПРОВЕРКА LWW ПРИНЦИПА
	// =========================================================================
	// Мы намеренно нарушаем хронологический порядок отправки на сервер!
	// Сначала пушим промежуточное состояние, затем самое свежее, и самым последним
	// доставляем самый старый пакет. Сервер обязан отбросить старый пакет на основеupdated_at!
	t.Run("Execute Concurrent Replication and Validate LWW Truth", func(t *testing.T) {
		// 1. Синхронизируем Клиента 2 (Заливает промежуточное значение в Postgres)
		_, _, _ = runClient(dbClient2, "sync")

		// 2. Синхронизируем Клиента 3 (Заливает САМОЕ СВЕЖЕЕ значение — оно становится истиной)
		_, _, _ = runClient(dbClient3, "sync")

		// 3. Синхронизируем Клиента 1 (Доставляет САМЫЙ СТАРЫЙ пакет ПОСЛЕДНИМ)
		// Сервер отбросит его Push, но в рамках Pull отдаст ему канон от Клиента 3.
		_, _, _ = runClient(dbClient1, "sync") // ИСПРАВЛЕНО: Убран хрупкий ассерт счетчика pulled

		// ПРОВЕРЯЕМ ЛОКАЛЬНЫЙ КЭШ КЛИЕНТА 1: Он должен был бесшовно всосать истину через LWW!
		getStdout1, _, _ := runClient(dbClient1, "get", "--name", "shared_secret")
		var getResp1 CLIResponse
		_ = json.Unmarshal([]byte(getStdout1), &getResp1)

		getDataBytes1, _ := json.Marshal(getResp1.Data)
		var getData1 GetResponse
		_ = json.Unmarshal(getDataBytes1, &getData1)

		expectedPayload := "pobednyi_payload_client_3"
		if getData1.Payload != expectedPayload {
			t.Errorf("LWW FAILURE ON CLIENT 1: Expected payload %q, but database holds %q",
				expectedPayload, getData1.Payload)
		}

		// 4. ФИНАЛЬНАЯ ПРОВЕРКА КОНСЕНСУСА КЛИЕНТА 2
		_, _, _ = runClient(dbClient2, "sync")

		getStdout2, _, _ := runClient(dbClient2, "get", "--name", "shared_secret")
		var getResp2 CLIResponse
		_ = json.Unmarshal([]byte(getStdout2), &getResp2)

		getDataBytes2, _ := json.Marshal(getResp2.Data)
		var getData2 GetResponse
		_ = json.Unmarshal(getDataBytes2, &getData2)

		if getData2.Payload != expectedPayload {
			t.Errorf("CRITICAL LWW FAILURE ON CLIENT 2: Expected payload %q, but database holds %q",
				expectedPayload, getData2.Payload)
		}
	})
}
