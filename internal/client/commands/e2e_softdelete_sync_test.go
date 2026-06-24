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

// TestE2E_SoftDelete_Synchronization проверяет сквозную синхронизацию мягкого удаления
func TestE2E_SoftDelete_Synchronization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soft delete E2E tests in short mode")
	}

	// Уникальный префикс для этого теста, чтобы не пересекаться с другими E2E тестами
	testPrefix := fmt.Sprintf("sd_%d_", time.Now().UnixNano())

	// 1. ИЗОЛЯЦИЯ ОКРУЖЕНИЯ
	tmpDir, err := os.MkdirTemp("", "gophkeeper-e2e-softdelete-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	dbClient1 := filepath.Join(tmpDir, "client_1.db")
	dbClient2 := filepath.Join(tmpDir, "client_2.db")
	dbClient3 := filepath.Join(tmpDir, "client_3.db")

	clientBinary, err := filepath.Abs("../../../build/linux/gophkeeper")
	require.NoError(t, err)
	serverBinary, err := filepath.Abs("../../../build/linux/gophkeeper-server")
	require.NoError(t, err)

	_, err = os.Stat(clientBinary)
	require.NoError(t, err, "client binary not found")
	_, err = os.Stat(serverBinary)
	require.NoError(t, err, "server binary not found")

	// 2. ЗАПУСК СЕРВЕРА
	serverTargetAddr := "127.0.0.1:9555"
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

	// Хелпер для получения списка записей с клиента
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

	// Хелпер для проверки наличия записей
	assertRecordsEqual := func(t *testing.T, dbPath string, expected []string) {
		t.Helper()
		names, err := getRecordNames(dbPath)
		require.NoError(t, err)
		assert.ElementsMatch(t, expected, names, "DB: %s", dbPath)
	}

	// =========================================================================
	// ЭТАП 1: ИНИЦИАЛИЗАЦИЯ И РЕГИСТРАЦИЯ ТРЕХ КЛИЕНТОВ
	// =========================================================================
	t.Log("=== Step 1: Initialize and register 3 clients ===")

	clients := []string{dbClient1, dbClient2, dbClient3}
	for i, db := range clients {
		_, _, err := runClient(db, "init")
		require.NoError(t, err, "client %d init failed", i+1)

		_, stderr, err := runClient(db, "register", "--server", serverTargetAddr)
		require.NoError(t, err, "client %d register failed: %s", i+1, stderr)
	}

	// =========================================================================
	// ЭТАП 2: КАЖДЫЙ КЛИЕНТ СОЗДАЕТ ПО 5 ЗАПИСЕЙ
	// =========================================================================
	t.Log("=== Step 2: Each client creates 5 records ===")

	// Клиент 1
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("%sclient1_rec_%d", testPrefix, i)
		_, stderr, err := runClient(dbClient1, "create",
			"--name", name,
			"--type", "text",
			"--payload", fmt.Sprintf("payload_1_%d", i),
		)
		require.NoError(t, err, "client 1 create %s failed: %s", name, stderr)
	}

	// Клиент 2
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("%sclient2_rec_%d", testPrefix, i)
		_, stderr, err := runClient(dbClient2, "create",
			"--name", name,
			"--type", "text",
			"--payload", fmt.Sprintf("payload_2_%d", i),
		)
		require.NoError(t, err, "client 2 create %s failed: %s", name, stderr)
	}

	// Клиент 3
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("%sclient3_rec_%d", testPrefix, i)
		_, stderr, err := runClient(dbClient3, "create",
			"--name", name,
			"--type", "text",
			"--payload", fmt.Sprintf("payload_3_%d", i),
		)
		require.NoError(t, err, "client 3 create %s failed: %s", name, stderr)
	}

	// Проверяем, что у каждого клиента по 5 записей
	expectedClient1 := []string{"client1_rec_1", "client1_rec_2", "client1_rec_3", "client1_rec_4", "client1_rec_5"}
	expectedClient2 := []string{"client2_rec_1", "client2_rec_2", "client2_rec_3", "client2_rec_4", "client2_rec_5"}
	expectedClient3 := []string{"client3_rec_1", "client3_rec_2", "client3_rec_3", "client3_rec_4", "client3_rec_5"}

	assertRecordsEqual(t, dbClient1, expectedClient1)
	assertRecordsEqual(t, dbClient2, expectedClient2)
	assertRecordsEqual(t, dbClient3, expectedClient3)

	// =========================================================================
	// ЭТАП 3: КЛИЕНТ 1 СИНХРОНИЗИРУЕТСЯ
	// =========================================================================
	t.Log("=== Step 3: Client 1 syncs (5 records to server) ===")

	_, stderr, err := runClient(dbClient1, "sync")
	require.NoError(t, err, "client 1 sync failed: %s", stderr)
	assertRecordsEqual(t, dbClient1, expectedClient1)

	// =========================================================================
	// ЭТАП 4: КЛИЕНТ 2 СИНХРОНИЗИРУЕТСЯ
	// =========================================================================
	t.Log("=== Step 4: Client 2 syncs (10 records: 5 own + 5 from client 1) ===")

	_, stderr, err = runClient(dbClient2, "sync")
	require.NoError(t, err, "client 2 sync failed: %s", stderr)

	expectedClient2AfterSync := []string{
		"client2_rec_1", "client2_rec_2", "client2_rec_3", "client2_rec_4", "client2_rec_5",
		"client1_rec_1", "client1_rec_2", "client1_rec_3", "client1_rec_4", "client1_rec_5",
	}
	assertRecordsEqual(t, dbClient2, expectedClient2AfterSync)

	// =========================================================================
	// ЭТАП 5: КЛИЕНТ 2 УДАЛЯЕТ 2 ЗАПИСИ
	// =========================================================================
	t.Log("=== Step 5: Client 2 deletes 2 records (1 own, 1 from client 1) ===")

	client2OwnID, err := getRecordID(dbClient2, "client2_rec_3")
	require.NoError(t, err)

	client1RecID, err := getRecordID(dbClient2, "client1_rec_2")
	require.NoError(t, err)

	_, stderr, err = runClient(dbClient2, "delete", "--id", client2OwnID)
	require.NoError(t, err, "delete client2_rec_3 failed: %s", stderr)

	_, stderr, err = runClient(dbClient2, "delete", "--id", client1RecID)
	require.NoError(t, err, "delete client1_rec_2 failed: %s", stderr)

	expectedClient2AfterDelete := []string{
		"client2_rec_1", "client2_rec_2", "client2_rec_4", "client2_rec_5",
		"client1_rec_1", "client1_rec_3", "client1_rec_4", "client1_rec_5",
	}
	assertRecordsEqual(t, dbClient2, expectedClient2AfterDelete)

	// =========================================================================
	// ЭТАП 6: КЛИЕНТ 2 СИНХРОНИЗИРУЕТСЯ
	// =========================================================================
	t.Log("=== Step 6: Client 2 syncs (deletions go to server) ===")

	_, stderr, err = runClient(dbClient2, "sync")
	require.NoError(t, err, "client 2 sync after delete failed: %s", stderr)
	assertRecordsEqual(t, dbClient2, expectedClient2AfterDelete)

	// =========================================================================
	// ЭТАП 7: КЛИЕНТ 3 СИНХРОНИЗИРУЕТСЯ
	// =========================================================================
	t.Log("=== Step 7: Client 3 syncs (13 records: 5 own + 4 from client 1 + 4 from client 2) ===")

	_, stderr, err = runClient(dbClient3, "sync")
	require.NoError(t, err, "client 3 sync failed: %s", stderr)

	expectedClient3 := []string{
		"client3_rec_1", "client3_rec_2", "client3_rec_3", "client3_rec_4", "client3_rec_5",
		"client1_rec_1", "client1_rec_3", "client1_rec_4", "client1_rec_5",
		"client2_rec_1", "client2_rec_2", "client2_rec_4", "client2_rec_5",
	}
	assertRecordsEqual(t, dbClient3, expectedClient3)

	// =========================================================================
	// ЭТАП 8: КЛИЕНТ 1 СИНХРОНИЗИРУЕТСЯ
	// =========================================================================
	t.Log("=== Step 8: Client 1 syncs (receives deletions from client 2) ===")

	_, stderr, err = runClient(dbClient1, "sync")
	require.NoError(t, err, "client 1 sync after delete failed: %s", stderr)

	expectedClient1AfterDelete := []string{
		"client1_rec_1", "client1_rec_3", "client1_rec_4", "client1_rec_5",
	}
	assertRecordsEqual(t, dbClient1, expectedClient1AfterDelete)

	// =========================================================================
	// ЭТАП 9: ФИНАЛЬНАЯ ПРОВЕРКА ВСЕХ КЛИЕНТОВ
	// =========================================================================
	t.Log("=== Step 9: Final verification of all clients ===")

	assertRecordsEqual(t, dbClient1, expectedClient1AfterDelete)
	assertRecordsEqual(t, dbClient2, expectedClient2AfterDelete)
	assertRecordsEqual(t, dbClient3, expectedClient3)

	// =========================================================================
	// ЭТАП 10: ПРОВЕРКА ЧТО УДАЛЕННЫЕ ЗАПИСИ НЕ ДОСТУПНЫ ЧЕРЕЗ GET
	// =========================================================================
	t.Log("=== Step 10: Verify deleted records are not accessible via get ===")

	for _, db := range []string{dbClient1, dbClient2, dbClient3} {
		fullName := testPrefix + "client1_rec_2"
		stdout, _, err := runClient(db, "get", "--name", fullName)
		require.NoError(t, err)

		var resp CLIResponse
		err = json.Unmarshal([]byte(stdout), &resp)
		require.NoError(t, err)
		assert.False(t, resp.Success, "client1_rec_2 should be deleted on %s", db)
		assert.Contains(t, resp.Error, "secret record not found", "error should indicate not found on %s", db)
	}

	// Проверяем, что client2_rec_3 удален на всех клиентах
	for _, db := range []string{dbClient1, dbClient2, dbClient3} {
		fullName := testPrefix + "client2_rec_3"
		stdout, _, err := runClient(db, "get", "--name", fullName)
		require.NoError(t, err)

		var resp CLIResponse
		err = json.Unmarshal([]byte(stdout), &resp)
		require.NoError(t, err)
		assert.False(t, resp.Success, "client2_rec_3 should be deleted on %s", db)
		assert.Contains(t, resp.Error, "secret record not found", "error should indicate not found on %s", db)
	}

	// Проверяем, что живые записи доступны
	for _, db := range []string{dbClient1, dbClient2, dbClient3} {
		fullName := testPrefix + "client1_rec_1"
		stdout, _, err := runClient(db, "get", "--name", fullName)
		require.NoError(t, err)

		var resp CLIResponse
		err = json.Unmarshal([]byte(stdout), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Success, "client1_rec_1 should be accessible on %s", db)
	}

	t.Log("=== ✅ All tests passed! Soft delete synchronization works correctly ===")
}
