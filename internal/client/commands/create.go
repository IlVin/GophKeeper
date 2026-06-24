// Package commands предоставляет реализации консольных команд Cobra для
// криптографического взаимодействия с хранилищем GophKeeper.
package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/service"
	"gophkeeper/internal/client/sshcheck"
	"gophkeeper/internal/domain/security"

	"github.com/spf13/cobra"
)

// Максимальный лимит размера файла (10 Мегабайт) для MVP-защиты оперативной памяти.
const maxBinarySize = 10 * 1024 * 1024

var (
	// ErrInvalidSecretType возвращается, если указан неподдерживаемый тип записи.
	ErrInvalidSecretType = errors.New("unsupported secret type: allowed credentials, text, binary, card")
)

// newCreateCommand конструирует CLI-команду "create" для запечатывания
// и сохранения новой приватной записи в локальном сейфе.
func newCreateCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Seal and save a new secret record to storage",
		Long:  `Encrypts data with XChaCha20-Poly1305 under AccountMasterKey and protects metadata from leakage.`,
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			slog.Info("Starting record encryption and creation command")

			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ssh-agent check error")
			}

			// Разбор и валидация входящих аргументов
			flags := cmd.Flags()
			name, _ := flags.GetString("name")
			secretType, _ := flags.GetString("type")
			payloadStr, _ := flags.GetString("payload")
			filePath, _ := flags.GetString("file")
			metaStr, _ := flags.GetString("meta")

			name = strings.TrimSpace(name)
			secretType = strings.ToLower(strings.TrimSpace(secretType))

			if name == "" || secretType == "" {
				return cli.PrintError(out, errors.New("--name and --type are required and cannot be empty"), "flag validation")
			}

			// Проверка доменного инварианта типов секретов
			switch secretType {
			case "credentials", "text", "binary", "card":
				// Тип валиден
			default:
				return cli.PrintError(out, fmt.Errorf("%w: %q", ErrInvalidSecretType, secretType), "flag validation")
			}

			// Извлечение метаданных
			metadataMap, err := parseMetadata(metaStr)
			if err != nil {
				return cli.PrintError(out, err, "metadata params")
			}

			// Извлечение полезной нагрузки (внутри происходит RAM-контроль размера файла)
			finalPayload, err := resolvePayload(secretType, payloadStr, filePath)
			if err != nil {
				return cli.PrintError(out, err, "reading record content")
			}

			// Упаковываем payload и metadata в единый монолитный блок (Защита от Metadata Leakage)
			plainBytes, err := security.PackRecordPlaintext(finalPayload, metadataMap)
			if err != nil {
				security.SecretBytes(finalPayload).Destroy() // Очищаем RAM при сбое
				return cli.PrintError(out, err, "cryptographic plaintext packing")
			}

			// Гарантируем уничтожение сырых данных в памяти по выходу из конвейера
			defer func() {
				security.SecretBytes(plainBytes).Destroy()
				security.SecretBytes(finalPayload).Destroy()
				slog.Debug("Secret raw bytes successfully wiped from RAM (RAM Hygiene)")
			}()

			// Открываем существующее изолированное рантайм окружение приложения
			app, err := cli.App(ctx)
			if err != nil {
				return cli.PrintError(out, err, "application context startup")
			}

			// Сборка зависимостей внутри Composition Root команды
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "connect to ssh-agent socket")
			}

			agentClosedChecked := false
			defer func() {
				if !agentClosedChecked {
					if closeErr := agentClient.Close(); closeErr != nil {
						slog.Error("Failed to close UNIX agent socket in create defer", "error", closeErr)
					}
				}
			}()

			secretStore := sqlite.NewSQLiteSecretStore(app.DB())
			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB())
			secretService := service.NewSecretService(secretStore, deviceStore, agentClient)

			// Запускаем криптографический конвейер шифрования записи XChaCha20-Poly1305
			slog.Info("Sending monolithic package to cryptographic encryption service")
			err = secretService.CreateSecret(ctx, name, secretType, plainBytes)
			if err != nil {
				return cli.PrintError(out, err, "cryptographic record save failure")
			}

			// Безопасно финализируем соединение с агентом до вывода результатов
			if closeErr := agentClient.Close(); closeErr != nil {
				slog.Error("Failed to close agent socket descriptor on successful exit", "error", closeErr)
			}
			agentClosedChecked = true

			payloadOut := CreateResponse{
				Name: name,
				Type: secretType,
			}

			cli.PrintResult(out, payloadOut, func() {
				fmt.Fprintf(out, "Opening master envelope via ssh-agent and sealing record %q...\n", name)
				fmt.Fprintf(out, "[OK] SUCCESS! Record %q [%s] securely encrypted and saved under AccountMasterKey.\n", name, secretType)
			})

			return nil
		}),
	}

	// Регистрация эфемерных флагов
	cmd.Flags().String("name", "", "Unique human-readable record name for lookup")
	cmd.Flags().String("type", "", "Type of secret to encrypt (credentials, text, binary, card)")
	cmd.Flags().String("payload", "", "Text content of the secret (password, token, string)")
	cmd.Flags().String("file", "", "Absolute path to binary file on disk (only for --type=binary)")
	cmd.Flags().String("meta", "{}", "Additional metadata in flat JSON format .{\"key\":\"value\"}.")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("type")

	return cmd
}

// parseMetadata парсит и изолирует валидацию строки метаданных
func parseMetadata(metaStr string) (map[string]string, error) {
	var metadataMap map[string]string
	if err := json.Unmarshal([]byte(metaStr), &metadataMap); err != nil {
		slog.Error("--meta flag parsing failed with syntax error", "error", err)
		return nil, fmt.Errorf("invalid --meta format: must be a valid flat JSON object like .{\"key\": \"value\"}.")
	}
	return metadataMap, nil
}

// resolvePayload изолирует чтение и RAM-контроль входящих данных по типу секрета
func resolvePayload(secretType, payloadStr, filePath string) ([]byte, error) {
	if secretType == "binary" {
		if strings.TrimSpace(filePath) == "" {
			return nil, errors.New("--file flag is required when secret type is .binary.")
		}

		fileInfo, err := os.Stat(filePath)
		if err != nil {
			slog.Error("Failed to stat specified binary file", "path", filePath, "error", err)
			return nil, fmt.Errorf("file %q not found or inaccessible", filePath)
		}

		if fileInfo.Size() > maxBinarySize {
			slog.Warn("Blocked attempt to upload file exceeding MVP limits", "size", fileInfo.Size())
			return nil, fmt.Errorf("file size exceeds security limit of 10 MB (provided: %d bytes)", fileInfo.Size())
		}

		finalPayload, err := os.ReadFile(filePath)
		if err != nil {
			slog.Error("Failed reading binary file from disk to heap", "path", filePath, "error", err)
			return nil, fmt.Errorf("binary file read error")
		}
		return finalPayload, nil
	}

	if strings.TrimSpace(payloadStr) == "" {
		return nil, fmt.Errorf("--payload cannot be empty for secret type .%s.", secretType)
	}
	return []byte(payloadStr), nil
}
