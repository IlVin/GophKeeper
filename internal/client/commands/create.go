package commands

import (
	"fmt"
	"os"
	"strings"

	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/service"
	"gophkeeper/internal/client/sshcheck"

	"github.com/spf13/cobra"
)

const maxBinarySize = 10 * 1024 * 1024 // 10 MB MVP Limit

func newCreateCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create and encrypt a new private record inside the vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			// 1. Проверяем матрицу Preconditions (Инвариант №4: SSH Agent обязателен)
			if err := sshcheck.RequireAgent(); err != nil {
				return fmt.Errorf("%w\n\n%s", err, sshcheck.FormatSSHAgentHelp())
			}

			// Разбираем эфемерные флаги
			flags := cmd.Flags()
			name, _ := flags.GetString("name")
			secretType, _ := flags.GetString("type")
			payloadStr, _ := flags.GetString("payload")
			filePath, _ := flags.GetString("file")

			name = strings.TrimSpace(name)
			secretType = strings.ToLower(strings.TrimSpace(secretType))

			if name == "" || secretType == "" {
				return fmt.Errorf("parameters --name and --type are mandatory and cannot be empty")
			}

			// 2. Валидация входных данных по типу секрета
			var finalPayload []byte
			var err error

			if secretType == "binary" {
				if filePath == "" {
					return fmt.Errorf("--file path is required when --type is set to 'binary'")
				}
				// Проверяем MVP лимит на размер файла перед чтением в память
				fileInfo, err := os.Stat(filePath)
				if err != nil {
					return fmt.Errorf("failed to stat file %q: %w", filePath, err)
				}
				if fileInfo.Size() > maxBinarySize {
					return fmt.Errorf("file size exceeds MVP limit of 10 Megabytes (got %d bytes)", fileInfo.Size())
				}

				finalPayload, err = os.ReadFile(filePath)
				if err != nil {
					return fmt.Errorf("failed to read binary file: %w", err)
				}
			} else {
				if payloadStr == "" {
					return fmt.Errorf("--payload content is required for type '%s'", secretType)
				}
				finalPayload = []byte(payloadStr)
			}

			// 3. Открываем существующее runtime окружение приложения
			app, err := cli.App(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to open application runtime: %w", err)
			}

			// 4. Инициализируем провайдеры и сервис «на лету» внутри Composition Root
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return fmt.Errorf("connect to ssh-agent: %w", err)
			}
			defer agentClient.Close()

			secretStore := sqlite.NewSQLiteSecretStore(app.DB)
			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB)
			secretService := service.NewSecretService(secretStore, deviceStore, agentClient)

			// 5. Запускаем криптографический конвейер шифрования записи
			fmt.Fprintf(out, "Unlocking master key via ssh-agent and encrypting record %q...\n", name)

			err = secretService.CreateSecret(cmd.Context(), name, secretType, finalPayload)
			if err != nil {
				return fmt.Errorf("failed to encrypt and save record: %w", err)
			}

			fmt.Fprintf(out, "✔ Success! Record %q [%s] securely saved and protected under AccountMasterKey.\n", name, secretType)
			return nil
		},
	}

	// Регистрируем эфемерные флаги
	cmd.Flags().String("name", "", "Human-readable unique identifier for searching")
	cmd.Flags().String("type", "", "Type of secret (credentials, text, binary, card)")
	cmd.Flags().String("payload", "", "Secret payload content (password, text data)")
	cmd.Flags().String("file", "", "Path to a binary file (only for --type=binary)")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("type")

	return cmd
}
