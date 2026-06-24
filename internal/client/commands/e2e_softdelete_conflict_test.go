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

	// Хелпер для получения payload записи по ID
	getRecordPayloadByID := func(dbPath, id string) (string, error) {
		stdout, _, err := runClient(dbPath, "get", "--id", id)
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

	// Хелпер для получения payload записи по имени
	getRecordPayloadByName := func(dbPath, name string) (string, error) {
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

	assertRecordsEqual(t, dbClient1, []string{recordName})

	sharedID, err := getRecordID(dbClient1, recordName)
	require.NoError(t, err)
	t.Logf("Record ID: %s", sharedID)

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

	assertRecordsEqual(t, dbClient2, []string{recordName})
	payload, err := getRecordPayloadByID(dbClient2, sharedID)
	require.NoError(t, err)
	assert.Equal(t, "v1", payload, "Client 2 should have payload 'v1'")

	// =========================================================================
	// ЭТАП 5: КЛИЕНТ 1 УДАЛЯЕТ ЗАПИСЬ "shared"
	// =========================================================================
	t.Log("=== Step 5: Client 1 deletes record 'shared' (is_deleted=1, updated_at=T1) ===")

	_, stderr, err = runClient(dbClient1, "delete", "--id", sharedID)
	require.NoError(t, err, "client 1 delete failed: %s", stderr)

	assertRecordsEqual(t, dbClient1, []string{})

	// =========================================================================
	// ЭТАП 6: КЛИЕНТ 2 ПЕРЕСОЗДАЕТ ЗАПИСЬ "shared" С PAYLOAD "v2"
	// =========================================================================
	t.Log("=== Step 6: Client 2 recreates record 'shared' with payload 'v2' (is_deleted=0, created_at=T2, updated_at=T2, T2 > T1) ===")

	_, stderr, err = runClient(dbClient2, "create",
		"--name", fullName,
		"--type", "text",
		"--payload", "v2",
	)
	require.NoError(t, err, "client 2 recreate failed: %s", stderr)

	assertRecordsEqual(t, dbClient2, []string{recordName})
	payload, err = getRecordPayloadByID(dbClient2, sharedID)
	require.NoError(t, err)
	assert.Equal(t, "v2", payload, "Client 2 should have payload 'v2'")

	// =========================================================================
	// ЭТАП 7: КЛИЕНТ 2 СИНХРОНИЗИРУЕТСЯ ПЕРВЫМ
	// =========================================================================
	t.Log("=== Step 7: Client 2 syncs first (sends v2 to server: is_deleted=0, created_at=T2, updated_at=T2) ===")

	_, stderr, err = runClient(dbClient2, "sync")
	require.NoError(t, err, "client 2 sync after recreate failed: %s", stderr)

	assertRecordsEqual(t, dbClient2, []string{recordName})
	payload, err = getRecordPayloadByID(dbClient2, sharedID)
	require.NoError(t, err)
	assert.Equal(t, "v2", payload, "Client 2 should have payload 'v2'")

	// =========================================================================
	// ЭТАП 8: КЛИЕНТ 1 СИНХРОНИЗИРУЕТСЯ (ОТПРАВЛЯЕТ УДАЛЕНИЕ)
	// =========================================================================
	t.Log("=== Step 8: Client 1 syncs (sends deletion to server: is_deleted=1, updated_at=T1) ===")
	t.Log("=== Server applies LWW: T2 > T1 → Client 2's record wins, deletion is ignored ===")

	_, stderr, err = runClient(dbClient1, "sync")
	require.NoError(t, err, "client 1 sync after delete failed: %s", stderr)

	// =========================================================================
	// ДЕБАГ: ВЫВОДИМ СОСТОЯНИЕ КЛИЕНТА 1 ПОСЛЕ ПЕРВОЙ СИНХРОНИЗАЦИИ
	// =========================================================================
	t.Log("=== DEBUG: Client 1 state after first sync ===")

	// 1. Полный вывод list в JSON
	stdout, _, _ := runClient(dbClient1, "list")
	t.Logf("Client 1 list (raw): %s", stdout)

	// 2. Проверяем, есть ли запись через get --id
	t.Logf("Checking get --id %s on client 1", sharedID)
	payload1, err1 := getRecordPayloadByID(dbClient1, sharedID)
	if err1 != nil {
		t.Logf("get --id failed: %v", err1)
	} else {
		t.Logf("get --id payload: %q", payload1)
	}

	// 3. Проверяем, есть ли запись через get --name
	t.Logf("Checking get --name %s on client 1", recordName)
	payload2, err2 := getRecordPayloadByName(dbClient1, recordName)
	if err2 != nil {
		t.Logf("get --name failed: %v", err2)
	} else {
		t.Logf("get --name payload: %q", payload2)
	}

	// 4. Проверяем список имен
	names1, _ := getRecordNames(dbClient1)
	t.Logf("Client 1 record names: %v", names1)

	// =========================================================================
	// ЭТАП 9: КЛИЕНТ 1 СИНХРОНИЗИРУЕТСЯ ЕЩЕ РАЗ
	// =========================================================================
	t.Log("=== Step 9: Client 1 syncs again (ensures v2 is persisted) ===")

	_, stderr, err = runClient(dbClient1, "sync")
	require.NoError(t, err, "client 1 second sync failed: %s", stderr)

	// =========================================================================
	// ДЕБАГ: ВЫВОДИМ СОСТОЯНИЕ КЛИЕНТА 1 ПОСЛЕ ВТОРОЙ СИНХРОНИЗАЦИИ
	// =========================================================================
	t.Log("=== DEBUG: Client 1 state after second sync ===")

	stdout, _, _ = runClient(dbClient1, "list")
	t.Logf("Client 1 list (raw): %s", stdout)

	payload1, err1 = getRecordPayloadByID(dbClient1, sharedID)
	if err1 != nil {
		t.Logf("get --id failed after second sync: %v", err1)
	} else {
		t.Logf("get --id payload after second sync: %q", payload1)
	}

	names1, _ = getRecordNames(dbClient1)
	t.Logf("Client 1 record names after second sync: %v", names1)

	// =========================================================================
	// ДЕБАГ: ВЫВОДИМ СОСТОЯНИЕ КЛИЕНТА 2
	// =========================================================================
	t.Log("=== DEBUG: Client 2 state ===")

	stdout, _, _ = runClient(dbClient2, "list")
	t.Logf("Client 2 list (raw): %s", stdout)

	payload3, err3 := getRecordPayloadByID(dbClient2, sharedID)
	if err3 != nil {
		t.Logf("get --id on client 2 failed: %v", err3)
	} else {
		t.Logf("get --id on client 2 payload: %q", payload3)
	}

	names2, _ := getRecordNames(dbClient2)
	t.Logf("Client 2 record names: %v", names2)

	// =========================================================================
	// ЭТАП 10: ФИНАЛЬНАЯ ПРОВЕРКА
	// =========================================================================
	t.Log("=== Step 10: Final verification ===")

	// Проверяем, что у клиента 1 есть запись "shared" в list
	assertRecordsEqual(t, dbClient1, []string{recordName})

	// Проверяем, что у клиента 2 есть запись "shared" в list
	assertRecordsEqual(t, dbClient2, []string{recordName})

	// Проверяем payload через get --id на клиенте 1
	payloadFinal, err := getRecordPayloadByID(dbClient1, sharedID)
	require.NoError(t, err, "Client 1 should have payload via get --id")
	assert.Equal(t, "v2", payloadFinal, "Client 1 should have payload 'v2'")

	// Проверяем payload через get --id на клиенте 2
	payloadFinal, err = getRecordPayloadByID(dbClient2, sharedID)
	require.NoError(t, err, "Client 2 should have payload via get --id")
	assert.Equal(t, "v2", payloadFinal, "Client 2 should have payload 'v2'")

	// =========================================================================
	// ОЧИСТКА
	// =========================================================================
	t.Log("=== Step 11: Cleanup — removing test records ===")

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
