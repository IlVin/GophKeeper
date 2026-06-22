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
				t.Fatalf("client_%d register failed: %v, stderr: %s, server logs: %s", i+1, err, stderr, serverStderr.String())
			}

			var resp CLIResponse
			_ = json.Unmarshal([]byte(stdout), &resp)
			if !resp.Success {
				t.Fatalf("server rejected registration for client_%d: %s", i+1, resp.Error)
			}
		}
	})

	// =========================================================================
	// ЭТАП 2: ФОРМИРОВАНИЕ ОФФЛАЙН КОНФЛИКТА (Last-Write-Wins Тест-кейс)
	// =========================================================================
	// Симулируем ситуацию: три клиента в оффлайне одновременно создают/изменяют
	// запись с ОДНИМ И ТЕМ ЖЕ ИМЕНЕМ 'shared_secret', но с разным payload.
	t.Run("Generate Competitive Offline State Mutations", func(t *testing.T) {
		// Клиент 1: Создает запись первым (Самая ранняя метка времени)
		_, _, _ = runClient(dbClient1, "create", "--name", "shared_secret", "--type", "text", "--payload", "value_from_client_1")
		time.Sleep(1 * time.Second) // Искусственная задержка для разделения временных меток updated_at

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

		// 2. Синхронизируем Клиента 3 (Заливает САМОЕ СВЕЖЕЕ значение — оно должно стать истиной в облаке)
		_, _, _ = runClient(dbClient3, "sync")

		// 3. Синхронизируем Клиента 1 (Доставляет САМЫЙ СТАРЫЙ пакет ПОСЛЕДНИМ по времени доставки)
		// Сервер Stateful Blind Storage обязан увидеть, что в СУБД уже лежитupdated_at новее,
		// проигнорировать этот Push, но выполнить Pull, отдав Клиенту 1 свежую истину!
		stdout, _, _ := runClient(dbClient1, "sync")

		var resp CLIResponse
		_ = json.Unmarshal([]byte(stdout), &resp)

		dataBytes, _ := json.Marshal(resp.Data)
		var syncData SyncResponse
		_ = json.Unmarshal(dataBytes, &syncData)

		// Клиент 1 должен был скачать 1 запись из облака (потому что его локальная запись устарела)
		if syncData.Pulled != 1 {
			t.Errorf("Expected Client 1 to pull the latest update from cloud, got pulled: %d", syncData.Pulled)
		}

		// 4. ФИНАЛЬНАЯ ПРОВЕРКА КОНСЕНСУСА: Делаем sync для всех, чтобы выровнять стейт
		_, _, _ = runClient(dbClient2, "sync")

		// Проверяем, что теперь лежит в кэше Клиента 2 при чтении
		getStdout, _, _ := runClient(dbClient2, "get", "--name", "shared_secret")

		var getResp CLIResponse
		_ = json.Unmarshal([]byte(getStdout), &getResp)

		getDataBytes, _ := json.Marshal(getResp.Data)
		var getData GetResponse
		_ = json.Unmarshal(getDataBytes, &getData)

		// ГЛАВНЫЙ КРИПТОГРАФИЧЕСКИЙ АССЕРТ: Победить должен был payload от Клиента 3!
		expectedPayload := "pobednyi_payload_client_3"
		if getData.Payload != expectedPayload {
			t.Errorf("CRITICAL LWW FAILURE: Conflict resolution collapsed. Expected payload %q, but database holds %q",
				expectedPayload, getData.Payload)
		}
	})
}
