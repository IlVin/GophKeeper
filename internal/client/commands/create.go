package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/service"
	"gophkeeper/internal/client/sshcheck"
	"gophkeeper/internal/domain/security"

	"github.com/spf13/cobra"
)

const maxBinarySize = 10 * 1024 * 1024 // 10 MB MVP Limit

func newCreateCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create and encrypt a new private record inside the vault",
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			// 1. Проверяем матрицу Preconditions (Инвариант №4: SSH Agent обязателен)
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ssh agent error")
			}

			// Разбираем эфемерные флаги
			flags := cmd.Flags()
			name, _ := flags.GetString("name")
			secretType, _ := flags.GetString("type")
			payloadStr, _ := flags.GetString("payload")
			filePath, _ := flags.GetString("file")
			metaStr, _ := flags.GetString("meta")

			// Валидируем и парсим JSON-строку метаданных в map[string]string (Скрытие метаданных)
			var metadataMap map[string]string
			if err := json.Unmarshal([]byte(metaStr), &metadataMap); err != nil {
				return cli.PrintError(out, err, "invalid --meta format: parameter must be a valid flat JSON object '{\"key\": \"value\"}'")
			}

			name = strings.TrimSpace(name)
			secretType = strings.ToLower(strings.TrimSpace(secretType))

			if name == "" || secretType == "" {
				return cli.PrintError(out, fmt.Errorf("parameters --name and --type are mandatory and cannot be empty"), "validation failed")
			}

			// 2. Валидация входных данных по типу секрета
			var finalPayload []byte
			var err error

			if secretType == "binary" {
				if filePath == "" {
					return cli.PrintError(out, fmt.Errorf("--file path is required when --type is set to 'binary'"), "validation failed")
				}
				// Проверяем MVP лимит на размер файла перед чтением в память (Защита СУБД)
				fileInfo, err := os.Stat(filePath)
				if err != nil {
					return cli.PrintError(out, err, fmt.Sprintf("failed to stat file %q", filePath))
				}
				if fileInfo.Size() > maxBinarySize {
					return cli.PrintError(out, fmt.Errorf("file size exceeds MVP limit of 10 Megabytes (got %d bytes)", fileInfo.Size()), "file error")
				}

				finalPayload, err = os.ReadFile(filePath)
				if err != nil {
					return cli.PrintError(out, err, "failed to read binary file")
				}
			} else {
				if payloadStr == "" {
					return cli.PrintError(out, fmt.Errorf("--payload content is required for type '%s'", secretType), "validation failed")
				}
				finalPayload = []byte(payloadStr)
			}

			// Упаковываем payload и metadata в единый plaintext JSON-блок (Защита от Metadata Leakage)
			plainBytes, err := security.PackRecordPlaintext(finalPayload, metadataMap)
			if err != nil {
				return cli.PrintError(out, err, "crypto error: failed to pack plaintext layout")
			}

			// Гарантируем зануление промежуточных байт структуры в куче
			defer func() {
				for i := range plainBytes {
					plainBytes[i] = 0
				}
				for i := range finalPayload {
					finalPayload[i] = 0
				}
			}()

			// 3. Открываем существующее runtime окружение приложения
			app, err := cli.App(cmd.Context())
			if err != nil {
				return cli.PrintError(out, err, "failed to open application runtime")
			}

			// 4. Инициализируем провайдеры и сервис «на лету» внутри Composition Root
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "connect to ssh-agent")
			}
			defer agentClient.Close()

			secretStore := sqlite.NewSQLiteSecretStore(app.DB)
			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB)
			secretService := service.NewSecretService(secretStore, deviceStore, agentClient)

			// 5. Запускаем криптографический конвейер шифрования записи
			err = secretService.CreateSecret(cmd.Context(), name, secretType, plainBytes)
			if err != nil {
				return cli.PrintError(out, err, "crypto error: failed to encrypt and save record")
			}

			// Выводим финальный результат работы команды через общий билдер
			payload := CreateResponse{
				Name: name,
				Type: secretType,
			}

			cli.PrintResult(out, payload, func() {
				fmt.Fprintf(out, "Unlocking master key via ssh-agent and encrypting record %q...\n", name)
				fmt.Fprintf(out, "✔ Success! Record %q [%s] securely saved and protected under AccountMasterKey.\n", name, secretType)
			})

			return nil
		}),
	}

	// Регистрируем эфемерные флаги
	cmd.Flags().String("name", "", "Human-readable unique identifier for searching")
	cmd.Flags().String("type", "", "Type of secret (credentials, text, binary, card)")
	cmd.Flags().String("payload", "", "Secret payload content (password, text data)")
	cmd.Flags().String("file", "", "Path to a binary file (only for --type=binary)")

	// ЛОКАЛЬНАЯ ОПЦИЯ КОМАНДЫ CREATE: Защищенный контекст метаинформации
	cmd.Flags().String("meta", "{}", "Optional metadata in flat JSON format object '{\"key\":\"value\"}'")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("type")

	return cmd
}
