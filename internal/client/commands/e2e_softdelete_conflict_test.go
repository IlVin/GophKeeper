//go:build e2e

package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_SoftDelete_ConflictWithRecreate проверяет граничный случай:
// - Клиент 1 удаляет запись (is_deleted=1, updated_at=T1)
// - Клиент 2 пересоздает эту же запись (is_deleted=0, created_at=T2, updated_at=T2, T2 > T1)
// - LWW должен победить: побеждает новая запись от клиента 2, так как T2 > T1
//
// Сценарий:
// 1. Клиент 1 создает запись "shared" с payload "v1" (created_at=T0, updated_at=T0)
// 2. Клиент 1 синхронизируется → на сервере "shared" v1
// 3. Клиент 2 синхронизируется → у клиента 2 "shared" v1
// 4. Клиент 1 удаляет запись "shared" (is_deleted=1, updated_at=T1, T1 > T0)
// 5. Клиент 2 пересоздает запись "shared" с payload "v2" (is_deleted=0, created_at=T2, updated_at=T2, T2 > T1)
// 6. Клиент 1 синхронизируется → отправляет удаление (is_deleted=1, updated_at=T1) на сервер
// 7. Клиент 2 синхронизируется → отправляет новую запись (is_deleted=0, created_at=T2, updated_at=T2) на сервер
// 8. Сервер применяет LWW: сравнивает updated_at (T2 > T1) → побеждает запись клиента 2
// 9. Клиент 1 синхронизируется → получает v2 с сервера
// 10. Все клиенты имеют запись "shared" с payload "v2" (is_deleted=0)
func TestE2E_SoftDelete_ConflictWithRecreate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soft delete conflict E2E test in short mode")
	}

	// Уникальный префикс для этого теста, чтобы не пересекаться с другими E2E тестами
	testPrefix := fmt.Sprintf("sd_conflict_%d_", time.Now().UnixNano())

	// 1. ИЗОЛЯЦИЯ ОКРУЖЕНИЯ
	tmpDir, err := os.MkdirTemp("", "gophkeeper-e2e-softdelete-conflict-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	dbClient1 := filepath.Join(tmpDir, "client_1.db")
	dbClient2 := filepath.Join(tmpDir, "client_2.db")

	clientBinary, err := filepath.Abs("../../../build/linux/gophkeeper")
	require.NoError(t, err)
	serverBinary, err := filepath.Abs("../../../build/linux/gophkeeper-server")
	require.NoError(t, err)

	_, err = os.Stat(clientBinary)
	require.NoError(t, err, "client binary not found at %q. Run 'make build-linux' first", clientBinary)
	_, err = os.Stat(serverBinary)
	require.NoError(t, err, "server binary not found at %q. Run 'make build-linux' first", serverBinary)

	// 2. ЗАПУСК СЕРВЕРА
	serverTargetAddr := "127.0.0.1:9556"
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

	err = serverCmd.Start()
	require.NoError(t, err, "failed to boot server")
	defer func() {
		if serverCmd.Process != nil {
			_ = serverCmd.Process.Kill()
		}
	}()

	time.Sleep(600 * time.Millisecond)

	// Утилитарный хелпер для выполнения команд клиента
	runClient := func(dbPath string, args ...string) (string, string, error) {
		baseArgs := []string{"--sqlite-path", dbPath, "--json"}
		finalArgs := append(baseArgs, args...)

		cmd := exec.Command(clientBinary, finalArgs...)
		cmd.Env = os.Environ()

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}

	// Хелпер для получения списка записей с клиента (только с нашим префиксом)
	getRecordNames := func(dbPath string) ([]string, error) {
		stdout, _, err := runClient(dbPath, "list")
		if err != nil {
			return nil, err
		}

		var resp CLIResponse
		if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
			return nil, err
		}
		if !resp.Success {
			return nil, fmt.Errorf("list failed: %s", resp.Error)
		}

		dataBytes, _ := json.Marshal(resp.Data)
		var items []ListResponseItem
		if err := json.Unmarshal(dataBytes, &items); err != nil {
			return nil, err
		}

		names := make([]string, 0, len(items))
		for _, item := range items {
			// Фильтруем только записи с нашим префиксом
			if strings.HasPrefix(item.Name, testPrefix) {
				names = append(names, strings.TrimPrefix(item.Name, testPrefix))
			}
		}
		return names, nil
	}

	// Хелпер для получения payload записи по имени
	getRecordPayload := func(dbPath, name string) (string, error) {
		fullName := testPrefix + name
		stdout, _, err := runClient(dbPath, "get", "--name", fullName)
		if err != nil {
			return "", err
		}

		var resp CLIResponse
		if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
			return "", err
		}
		if !resp.Success {
			return "", fmt.Errorf("get failed: %s", resp.Error)
		}

		dataBytes, _ := json.Marshal(resp.Data)
		var getData GetResponse
		if err := json.Unmarshal(dataBytes, &getData); err != nil {
			return "", err
		}
		return getData.Payload, nil
	}

	// Хелпер для получения ID записи по имени
	getRecordID := func(dbPath, name string) (string, error) {
		stdout, _, err := runClient(dbPath, "list")
		if err != nil {
			return "", err
		}

		var resp CLIResponse
		if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
			return "", err
		}
		if !resp.Success {
			return "", fmt.Errorf("list failed: %s", resp.Error)
		}

		dataBytes, _ := json.Marshal(resp.Data)
		var items []ListResponseItem
		if err := json.Unmarshal(dataBytes, &items); err != nil {
			return "", err
		}

		fullName := testPrefix + name
		for _, item := range items {
			if item.Name == fullName {
				return item.ID, nil
			}
		}
		return "", fmt.Errorf("record %q not found", name)
	}

	// Хелпер для проверки наличия записей
	assertRecordsEqual := func(t *testing.T, dbPath string, expected []string) {
		t.Helper()
		names, err := getRecordNames(dbPath)
		require.NoError(t, err)
		assert.ElementsMatch(t, expected, names, "DB: %s", dbPath)
	}

	recordName := "shared"

	// =========================================================================
	// ЭТАП 1: ИНИЦИАЛИЗАЦИЯ И РЕГИСТРАЦИЯ ДВУХ КЛИЕНТОВ
	// =========================================================================
	t.Log("=== Step 1: Initialize and register 2 clients ===")

	clients := []string{dbClient1, dbClient2}
	for i, db := range clients {
		_, _, err := runClient(db, "init")
		require.NoError(t, err, "client %d init failed", i+1)

		_, stderr, err := runClient(db, "register", "--server", serverTargetAddr)
		require.NoError(t, err, "client %d register failed: %s", i+1, stderr)
	}

	// =========================================================================
	// ЭТАП 2: КЛИЕНТ 1 СОЗДАЕТ ЗАПИСЬ "shared" v1
	// =========================================================================
	t.Log("=== Step 2: Client 1 creates record 'shared' with payload 'v1' ===")

	fullName := testPrefix + recordName
	_, stderr, err := runClient(dbClient1, "create",
		"--name", fullName,
		"--type", "text",
		"--payload", "v1",
	)
	require.NoError(t, err, "client 1 create failed: %s", stderr)

	// Проверяем, что у клиента 1 есть запись
	assertRecordsEqual(t, dbClient1, []string{recordName})

	// =========================================================================
	// ЭТАП 3: КЛИЕНТ 1 СИНХРОНИЗИРУЕТСЯ (v1 на сервер)
	// =========================================================================
	t.Log("=== Step 3: Client 1 syncs (v1 to server) ===")

	_, stderr, err = runClient(dbClient1, "sync")
	require.NoError(t, err, "client 1 sync failed: %s", stderr)

	// =========================================================================
	// ЭТАП 4: КЛИЕНТ 2 СИНХРОНИЗИРУЕТСЯ (получает v1)
	// =========================================================================
	t.Log("=== Step 4: Client 2 syncs (receives v1) ===")

	_, stderr, err = runClient(dbClient2, "sync")
	require.NoError(t, err, "client 2 sync failed: %s", stderr)

	// Проверяем, что у клиента 2 есть запись "shared" с payload "v1"
	assertRecordsEqual(t, dbClient2, []string{recordName})
	payload, err := getRecordPayload(dbClient2, recordName)
	require.NoError(t, err)
	assert.Equal(t, "v1", payload, "Client 2 should have payload 'v1'")

	// =========================================================================
	// ЭТАП 5: КЛИЕНТ 1 УДАЛЯЕТ ЗАПИСЬ "shared" (is_deleted=1, updated_at=T1)
	// =========================================================================
	t.Log("=== Step 5: Client 1 deletes record 'shared' (is_deleted=1, updated_at=T1) ===")

	sharedID, err := getRecordID(dbClient1, recordName)
	require.NoError(t, err)

	_, stderr, err = runClient(dbClient1, "delete", "--id", sharedID)
	require.NoError(t, err, "client 1 delete failed: %s", stderr)

	// Проверяем, что у клиента 1 запись удалена
	assertRecordsEqual(t, dbClient1, []string{})

	// =========================================================================
	// ЭТАП 6: КЛИЕНТ 2 ПЕРЕСОЗДАЕТ ЗАПИСЬ "shared" С PAYLOAD "v2"
	// (is_deleted=0, created_at=T2, updated_at=T2, T2 > T1)
	// =========================================================================
	t.Log("=== Step 6: Client 2 recreates record 'shared' with payload 'v2' (is_deleted=0, created_at=T2, updated_at=T2, T2 > T1) ===")

	// Клиент 2 создает запись с тем же именем, но новым payload
	_, stderr, err = runClient(dbClient2, "create",
		"--name", fullName,
		"--type", "text",
		"--payload", "v2",
	)
	require.NoError(t, err, "client 2 recreate failed: %s", stderr)

	// Проверяем, что у клиента 2 все еще есть запись с payload "v2"
	assertRecordsEqual(t, dbClient2, []string{recordName})
	payload, err = getRecordPayload(dbClient2, recordName)
	require.NoError(t, err)
	assert.Equal(t, "v2", payload, "Client 2 should have payload 'v2'")

	// =========================================================================
	// ЭТАП 7: КЛИЕНТ 1 СИНХРОНИЗИРУЕТСЯ (отправляет удаление на сервер)
	// Сервер получает: is_deleted=1, updated_at=T1
	// =========================================================================
	t.Log("=== Step 7: Client 1 syncs (sends deletion to server: is_deleted=1, updated_at=T1) ===")

	_, stderr, err = runClient(dbClient1, "sync")
	require.NoError(t, err, "client 1 sync after delete failed: %s", stderr)

	// Клиент 1 все еще без записи
	assertRecordsEqual(t, dbClient1, []string{})

	// =========================================================================
	// ЭТАП 8: КЛИЕНТ 2 СИНХРОНИЗИРУЕТСЯ (отправляет v2 на сервер)
	// Сервер получает: is_deleted=0, created_at=T2, updated_at=T2
	// Сервер применяет LWW: T2 > T1 → побеждает запись клиента 2
	// =========================================================================
	t.Log("=== Step 8: Client 2 syncs (sends v2 to server: is_deleted=0, created_at=T2, updated_at=T2) ===")
	t.Log("=== Server applies LWW: T2 > T1 → Client 2's record wins ===")

	_, stderr, err = runClient(dbClient2, "sync")
	require.NoError(t, err, "client 2 sync after recreate failed: %s", stderr)

	// Клиент 2 все еще имеет v2
	assertRecordsEqual(t, dbClient2, []string{recordName})
	payload, err = getRecordPayload(dbClient2, recordName)
	require.NoError(t, err)
	assert.Equal(t, "v2", payload, "Client 2 should have payload 'v2'")

	// =========================================================================
	// ЭТАП 9: КЛИЕНТ 1 СИНХРОНИЗИРУЕТСЯ (получает v2 с сервера)
	// =========================================================================
	t.Log("=== Step 9: Client 1 syncs (receives v2 from server) ===")

	_, stderr, err = runClient(dbClient1, "sync")
	require.NoError(t, err, "client 1 sync after server update failed: %s", stderr)

	// =========================================================================
	// ЭТАП 10: ФИНАЛЬНАЯ ПРОВЕРКА
	// =========================================================================
	t.Log("=== Step 10: Final verification ===")

	// У клиента 1 должна быть запись "shared" с payload "v2"
	assertRecordsEqual(t, dbClient1, []string{recordName})
	payload, err = getRecordPayload(dbClient1, recordName)
	require.NoError(t, err)
	assert.Equal(t, "v2", payload, "Client 1 should have payload 'v2' (received from server)")

	// У клиента 2 должна быть запись "shared" с payload "v2"
	assertRecordsEqual(t, dbClient2, []string{recordName})
	payload, err = getRecordPayload(dbClient2, recordName)
	require.NoError(t, err)
	assert.Equal(t, "v2", payload, "Client 2 should have payload 'v2'")

	// Проверяем, что сервер имеет v2 (через клиента 1)
	payload, err = getRecordPayload(dbClient1, recordName)
	require.NoError(t, err)
	assert.Equal(t, "v2", payload, "Server should have payload 'v2'")

	// =========================================================================
	// ЭТАП 11: ОЧИСТКА — удаляем тестовые записи
	// =========================================================================
	t.Log("=== Step 11: Cleanup — removing test records ===")

	// Получаем все записи с нашим префиксом на всех клиентах
	for _, db := range []string{dbClient1, dbClient2} {
		names, err := getRecordNames(db)
		require.NoError(t, err)

		for _, name := range names {
			id, err := getRecordID(db, name)
			if err != nil {
				t.Logf("Warning: could not get ID for %s: %v", name, err)
				continue
			}
			_, _, err = runClient(db, "delete", "--id", id)
			if err != nil {
				t.Logf("Warning: could not delete %s: %v", name, err)
			}
		}
	}

	t.Log("=== ✅ All tests passed! LWW correctly resolved delete vs recreate conflict ===")
	t.Log("   - Client 1 deletion (is_deleted=1, updated_at=T1) was overridden")
	t.Log("   - Client 2 recreation (is_deleted=0, created_at=T2, updated_at=T2, T2 > T1) won")
	t.Log("   - All clients have the newest version 'v2'")
}
