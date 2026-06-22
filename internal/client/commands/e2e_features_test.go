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

// TestE2E_FeaturesAndNegativeValidation тестирует команды list, delete
// и прогоняет негативные тест-кейсы валидации флага --json.
func TestE2E_FeaturesAndNegativeValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping features and negative validation E2E tests in short mode")
	}

	// 1. ИЗОЛЯЦИЯ ОКРУЖЕНИЯ: Создаем стерильный sandbox-каталог
	tmpDir, err := os.MkdirTemp("", "gophkeeper-e2e-features-*")
	if err != nil {
		t.Fatalf("failed to create secure sandbox directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testDBPath := filepath.Join(tmpDir, "goph_keeper_features_test.db")

	// Динамически вычисляем абсолютный путь к бинарнику клиента
	pathToBinary, err := filepath.Abs("../../../cmd/gophkeeper/gophkeeper")
	if err != nil {
		t.Fatalf("failed to resolve absolute path to binary: %v", err)
	}

	// Вспомогательный анонимный хелпер для атомарного выполнения CLI команд
	runCmd := func(args ...string) (string, string, error) {
		baseArgs := []string{"--sqlite-path", testDBPath, "--json"}
		finalArgs := append(baseArgs, args...)

		cmd := exec.Command(pathToBinary, finalArgs...)
		cmd.Env = os.Environ() // Пробрасываем сокет ssh-agent

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		return stdout.String(), stderr.String(), err
	}

	// Инициализируем чистую базу данных перед тестами
	_, _, _ = runCmd("init")

	// Наполняем базу двумя тестовыми секретами для проверки списков
	_, _, _ = runCmd("create", "--name", "secret_A", "--type", "text", "--payload", "data_A")
	_, _, _ = runCmd("create", "--name", "secret_B", "--type", "credentials", "--payload", "user:pass")

	// =========================================================================
	// ШАГ 1: ВЫДЕЛЕННЫЙ АССЕРТ НА КОМАНДУ 'list' В ФОРМАТЕ JSON
	// =========================================================================
	t.Run("Validate List Command Output Schema", func(t *testing.T) {
		stdout, stderr, err := runCmd("list")
		if err != nil {
			t.Fatalf("list command failed: %v, stderr: %s", err, stderr)
		}

		var resp CLIResponse
		if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
			t.Fatalf("failed to parse list JSON response: %v, raw stdout: %q", err, stdout)
		}

		if !resp.Success {
			t.Fatalf("list command returned success=false: %s", resp.Error)
		}

		// Перепакуем динамический интерфейс в жесткий слайс ListResponseItem
		dataBytes, _ := json.Marshal(resp.Data)
		var listData []ListResponseItem
		if err := json.Unmarshal(dataBytes, &listData); err != nil {
			t.Fatalf("failed to remap data to []ListResponseItem slice: %v", err)
		}

		// Проверяем, что в массиве вернулось ровно 2 созданных секрета
		if len(listData) != 2 {
			t.Errorf("expected exactly 2 records in list metadata, got %d", len(listData))
		}

		// Валидируем поля первого элемента списка
		foundA := false
		for _, item := range listData {
			if item.Name == "secret_A" {
				foundA = true
				if item.Type != "text" {
					t.Errorf("expected secret_A type to be 'text', got %q", item.Type)
				}
				if item.ID == "" || item.LastUpdated == "" {
					t.Errorf("secret metadata fields ID or LastUpdated are empty")
				}
			}
		}
		if !foundA {
			t.Errorf("expected secret_A to be present inside the list response")
		}
	})

	// =========================================================================
	// ШАГ 2: ТЕСТИРОВАНИЕ КОМАНДЫ УДАЛЕНИЯ 'delete'
	// =========================================================================
	t.Run("Execute Secret Deletion and Verify Purge", func(t *testing.T) {
		// Сначала выгребаем ID записи secret_A из списка, чтобы удалить её по UUID
		listStdout, _, _ := runCmd("list")
		var listResp CLIResponse
		_ = json.Unmarshal([]byte(listStdout), &listResp)
		dataBytes, _ := json.Marshal(listResp.Data)
		var listData []ListResponseItem
		_ = json.Unmarshal(dataBytes, &listData)

		var targetID string
		for _, item := range listData {
			if item.Name == "secret_A" {
				targetID = item.ID
				break
			}
		}

		// Вызываем команду delete, передавая полученный UUID записи
		stdout, stderr, err := runCmd("delete", "--id", targetID)
		if err != nil {
			t.Fatalf("delete command failed: %v, stderr: %s", err, stderr)
		}

		var deleteResp CLIResponse
		_ = json.Unmarshal([]byte(stdout), &deleteResp)
		if !deleteResp.Success {
			t.Fatalf("delete command returned success=false inside JSON envelope: %s", deleteResp.Error)
		}

		// ПРОВЕРКА ОЧИСТКИ: Вызываем list повторно и проверяем, что запись исчезла
		newListStdout, _, _ := runCmd("list")
		var listResp2 CLIResponse
		_ = json.Unmarshal([]byte(newListStdout), &listResp2)
		dataBytes2, _ := json.Marshal(listResp2.Data)
		var listData2 []ListResponseItem
		_ = json.Unmarshal(dataBytes2, &listData2)

		if len(listData2) != 1 {
			t.Errorf("expected exactly 1 record left inside vault after delete, got %d", len(listData2))
		}
		if listData2[0].Name == "secret_A" {
			t.Errorf("CRITICAL: secret_A is still present inside metadata cache after delete command call")
		}
	})

	// =========================================================================
	// ШАГ 3: НЕГАТИВНЫЕ ТЕСТ-КЕЙСЫ ВАЛИДАЦИИ С ФЛАГОМ --json
	// =========================================================================

	// Негативный тест А: Передача сломанного/невалидного JSON во флаг --meta
	t.Run("Negative Verification - Corrupted Meta Flag JSON", func(t *testing.T) {
		stdout, _, _ := runCmd("create", "--name", "fail_secret", "--type", "text", "--payload", "data", "--meta", "{invalid-json-schema}")

		var resp CLIResponse
		if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
			t.Fatalf("failed to decode error json envelope: %v, raw stdout: %q", err, stdout)
		}

		// ЖЕСТКИЙ АССЕРТ НЕГАТИВНОГО КАН ОНА
		if resp.Success {
			t.Error("CRITICAL SECURITY HOLE: create command returned success=true for a corrupted --meta JSON payload!")
		}
		if resp.Error == "" {
			t.Error("expected error message description inside JSON envelope, but field is empty")
		}
	})

	// Негативный тест Б: Попытка вызвать get для несуществующей записи
	t.Run("Negative Verification - Fetch Non-Existent Secret", func(t *testing.T) {
		stdout, _, _ := runCmd("get", "--name", "absent_secret_in_vault")

		var resp CLIResponse
		if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
			t.Fatalf("failed to decode error json envelope: %v", err)
		}

		if resp.Success {
			t.Error("CRITICAL: get command returned success=true for a non-existent record name key!")
		}
		if resp.Error == "" {
			t.Error("expected descriptive error string inside JSON envelope for missing record, got empty field")
		}
	})
}
