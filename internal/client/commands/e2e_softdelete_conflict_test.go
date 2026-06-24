//go:build e2e

package commands

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// dumpSQLiteTable подключается к SQLite БД и выводит содержимое таблицы records
func dumpSQLiteTable(t *testing.T, dbPath string, label string) {
	t.Helper()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Logf("[%s] SQLite DB does not exist: %s", label, dbPath)
		return
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Logf("[%s] Failed to open SQLite: %v", label, err)
		return
	}
	defer db.Close()

	rows, err := db.Query(`SELECT id, name, type, created_at, updated_at, is_deleted FROM records ORDER BY name;`)
	if err != nil {
		t.Logf("[%s] Failed to query records: %v", label, err)
		return
	}
	defer rows.Close()

	t.Logf("=== DUMP: %s (SQLite) ===", label)
	count := 0
	for rows.Next() {
		var id, name, typ, createdAt, updatedAt string
		var isDeleted int32
		if err := rows.Scan(&id, &name, &typ, &createdAt, &updatedAt, &isDeleted); err != nil {
			t.Logf("  Scan error: %v", err)
			continue
		}
		count++
		t.Logf("  [%d] id=%s name=%s type=%s created=%s updated=%s is_deleted=%d",
			count, id, name, typ, createdAt, updatedAt, isDeleted)
	}
	if count == 0 {
		t.Logf("  (empty)")
	}
	t.Logf("=== END DUMP: %s ===", label)
}

// dumpPostgresTable подключается к PostgreSQL и выводит содержимое таблицы records для данного user_id
func dumpPostgresTable(t *testing.T, dsn string, userID string, label string) {
	t.Helper()

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Logf("[%s] Failed to connect to PostgreSQL: %v", label, err)
		return
	}
	defer pool.Close()

	rows, err := pool.Query(ctx, `SELECT id, name, type, created_at, updated_at, is_deleted FROM records WHERE user_id = $1 ORDER BY name;`, userID)
	if err != nil {
		t.Logf("[%s] Failed to query PostgreSQL records: %v", label, err)
		return
	}
	defer rows.Close()

	t.Logf("=== DUMP: %s (PostgreSQL) ===", label)
	count := 0
	for rows.Next() {
		var id, name, typ string
		var createdAt, updatedAt time.Time
		var isDeleted int32
		if err := rows.Scan(&id, &name, &typ, &createdAt, &updatedAt, &isDeleted); err != nil {
			t.Logf("  Scan error: %v", err)
			continue
		}
		count++
		t.Logf("  [%d] id=%s name=%s type=%s created=%s updated=%s is_deleted=%d",
			count, id, name, typ, createdAt.Format(time.RFC3339), updatedAt.Format(time.RFC3339), isDeleted)
	}
	if count == 0 {
		t.Logf("  (empty)")
	}
	t.Logf("=== END DUMP: %s ===", label)
}

// getUserIDFromClient извлекает UserID из device_state таблицы SQLite
func getUserIDFromClient(t *testing.T, dbPath string) string {
	t.Helper()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Logf("Failed to open SQLite for userID: %v", err)
		return ""
	}
	defer db.Close()

	var userID sql.NullString
	err = db.QueryRow(`SELECT user_id FROM device_state WHERE id = 1;`).Scan(&userID)
	if err != nil {
		t.Logf("Failed to get user_id: %v", err)
		return ""
	}
	if !userID.Valid {
		return ""
	}
	return userID.String
}

// TestE2E_SoftDelete_ConflictWithRecreate проверяет граничный случай с полными дампами БД
func TestE2E_SoftDelete_ConflictWithRecreate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping soft delete conflict E2E test in short mode")
	}

	// Уникальный префикс для этого теста
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
	require.NoError(t, err, "client binary not found")
	_, err = os.Stat(serverBinary)
	require.NoError(t, err, "server binary not found")

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
			if strings.HasPrefix(item.Name, testPrefix) {
				names = append(names, strings.TrimPrefix(item.Name, testPrefix))
			}
		}
		return names, nil
	}

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

	userID1 := getUserIDFromClient(t, dbClient1)
	userID2 := getUserIDFromClient(t, dbClient2)
	t.Logf("UserID1: %s, UserID2: %s", userID1, userID2)

	dumpSQLiteTable(t, dbClient1, "Client1 after init+register")
	dumpSQLiteTable(t, dbClient2, "Client2 after init+register")
	dumpPostgresTable(t, postgresDSN, userID1, "PostgreSQL after init+register")

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

	dumpSQLiteTable(t, dbClient1, "Client1 after create v1")
	dumpSQLiteTable(t, dbClient2, "Client2 after create v1 (should be empty)")
	dumpPostgresTable(t, postgresDSN, userID1, "PostgreSQL after create v1")

	// =========================================================================
	// ЭТАП 3: КЛИЕНТ 1 СИНХРОНИЗИРУЕТСЯ (v1 на сервер)
	// =========================================================================
	t.Log("=== Step 3: Client 1 syncs (v1 to server) ===")

	_, stderr, err = runClient(dbClient1, "sync")
	require.NoError(t, err, "client 1 sync failed: %s", stderr)

	dumpSQLiteTable(t, dbClient1, "Client1 after sync v1 to server")
	dumpSQLiteTable(t, dbClient2, "Client2 after sync v1 to server")
	dumpPostgresTable(t, postgresDSN, userID1, "PostgreSQL after sync v1 to server")

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

	dumpSQLiteTable(t, dbClient1, "Client1 after client2 sync")
	dumpSQLiteTable(t, dbClient2, "Client2 after client2 sync (should have v1)")
	dumpPostgresTable(t, postgresDSN, userID1, "PostgreSQL after client2 sync")

	// =========================================================================
	// ЭТАП 5: КЛИЕНТ 1 УДАЛЯЕТ ЗАПИСЬ "shared"
	// =========================================================================
	t.Log("=== Step 5: Client 1 deletes record 'shared' (is_deleted=1, updated_at=T1) ===")

	_, stderr, err = runClient(dbClient1, "delete", "--id", sharedID)
	require.NoError(t, err, "client 1 delete failed: %s", stderr)

	assertRecordsEqual(t, dbClient1, []string{})

	dumpSQLiteTable(t, dbClient1, "Client1 after delete (should have is_deleted=1)")
	dumpSQLiteTable(t, dbClient2, "Client2 after delete (should still have v1)")
	dumpPostgresTable(t, postgresDSN, userID1, "PostgreSQL after delete (should still have v1)")

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

	dumpSQLiteTable(t, dbClient1, "Client1 after client2 recreate")
	dumpSQLiteTable(t, dbClient2, "Client2 after recreate v2")
	dumpPostgresTable(t, postgresDSN, userID1, "PostgreSQL after client2 recreate")

	// =========================================================================
	// ЭТАП 7: КЛИЕНТ 2 СИНХРОНИЗИРУЕТСЯ ПЕРВЫМ (отправляет v2 на сервер)
	// =========================================================================
	t.Log("=== Step 7: Client 2 syncs first (sends v2 to server: is_deleted=0, created_at=T2, updated_at=T2) ===")

	_, stderr, err = runClient(dbClient2, "sync")
	require.NoError(t, err, "client 2 sync after recreate failed: %s", stderr)

	assertRecordsEqual(t, dbClient2, []string{recordName})
	payload, err = getRecordPayloadByID(dbClient2, sharedID)
	require.NoError(t, err)
	assert.Equal(t, "v2", payload, "Client 2 should have payload 'v2'")

	dumpSQLiteTable(t, dbClient1, "Client1 before critical sync (should NOT have v2 yet)")
	dumpSQLiteTable(t, dbClient2, "Client2 after sync v2 to server")
	dumpPostgresTable(t, postgresDSN, userID1, "PostgreSQL after client2 sync v2 (should have is_deleted=0, updated_at=T2)")

	// =========================================================================
	// ЭТАП 8: КЛИЕНТ 1 СИНХРОНИЗИРУЕТСЯ (отправляет удаление, получает v2)
	// =========================================================================
	t.Log("=== Step 8: Client 1 syncs (sends deletion to server: is_deleted=1, updated_at=T1) ===")
	t.Log("=== Server applies LWW: T2 > T1 → Client 2's record wins, deletion is ignored ===")
	t.Log("=== Client 1 should receive v2 from server (record missing locally) ===")

	_, stderr, err = runClient(dbClient1, "sync")
	require.NoError(t, err, "client 1 sync after delete failed: %s", stderr)

	dumpSQLiteTable(t, dbClient1, "Client1 after critical sync (SHOULD have v2 with is_deleted=0)")
	dumpSQLiteTable(t, dbClient2, "Client2 after critical sync")
	dumpPostgresTable(t, postgresDSN, userID1, "PostgreSQL after critical sync (should have is_deleted=0, updated_at=T2)")

	// =========================================================================
	// ЭТАП 9: КЛИЕНТ 1 СИНХРОНИЗИРУЕТСЯ ЕЩЕ РАЗ
	// =========================================================================
	t.Log("=== Step 9: Client 1 syncs again (ensures v2 is persisted) ===")

	_, stderr, err = runClient(dbClient1, "sync")
	require.NoError(t, err, "client 1 second sync failed: %s", stderr)

	dumpSQLiteTable(t, dbClient1, "Client1 after second sync")
	dumpSQLiteTable(t, dbClient2, "Client2 after second sync")
	dumpPostgresTable(t, postgresDSN, userID1, "PostgreSQL after second sync")

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
	t.Log("=== Step 11: Cleanup ===")

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
}
