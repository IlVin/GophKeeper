package commands

import (
	"encoding/json"
	"fmt"

	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/service"
	"gophkeeper/internal/client/sshcheck"
	"gophkeeper/internal/domain/security"

	"github.com/spf13/cobra"
)

func newGetCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Decrypt and read a private secret from the vault by its name or ID",
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			// 1. Проверяем матрицу Preconditions (Инвариант №4: SSH Agent обязателен)
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ssh agent error")
			}

			// Читаем эфемерные флаги поиска
			flags := cmd.Flags()
			id, _ := flags.GetString("id")
			name, _ := flags.GetString("name")

			if id == "" && name == "" {
				return cli.PrintError(out, fmt.Errorf("you must provide either --name or --id flag to lookup a secret"), "validation failed")
			}

			// 2. Открываем существующее runtime окружение приложения
			app, err := cli.App(cmd.Context())
			if err != nil {
				return cli.PrintError(out, err, "failed to open application runtime")
			}

			// 3. Сборка зависимостей «на лету» внутри Composition Root
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "connect to ssh-agent")
			}
			defer agentClient.Close()

			secretStore := sqlite.NewSQLiteSecretStore(app.DB)
			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB)
			secretService := service.NewSecretService(secretStore, deviceStore, agentClient)

			// 4. Запускаем конвейер дешифрования записи
			var targetKey string
			var isFindByID bool

			if id != "" {
				targetKey = id
				isFindByID = true
			} else {
				targetKey = name
				isFindByID = false
			}

			// Вызов конвейера дешифрования (Возвращает монолитный расшифрованный JSON-блок)
			recordName, plainBytes, err := secretService.UnsealSecret(cmd.Context(), targetKey, isFindByID)
			if err != nil {
				return cli.PrintError(out, err, "failed to decrypt secret")
			}

			// Гарантируем очистку расшифрованного монолитного блока из памяти после вывода
			defer func() {
				for i := range plainBytes {
					plainBytes[i] = 0
				}
			}()

			// 5. РАСПАКОВКА СТРУКТУРЫ: Разделяем payload и metadata
			var plain security.RecordPlaintext
			if err := json.Unmarshal(plainBytes, &plain); err != nil {
				return cli.PrintError(out, err, "failed to parse decrypted secret payload layout")
			}

			// Гарантируем зануление полей структуры в куче (RAM Hygiene)
			defer func() {
				for i := range plain.Payload {
					plain.Payload[i] = 0
				}
				for k, v := range plain.Metadata {
					_ = k
					_ = v
					// Текстовые строки неизменяемы в Go, но очистка ссылок
					// ускоряет работу GC по уничтожению метаданных в куче
					delete(plain.Metadata, k)
				}
			}()

			// Выводим финальный результат работы команды
			payload := GetResponse{
				Name:     recordName,
				Payload:  string(plain.Payload),
				Metadata: plain.Metadata,
			}

			cli.PrintResult(out, payload, func() {
				if id != "" {
					fmt.Fprintf(out, "Unlocking vault and fetching record by ID %q...\n", id)
				} else {
					fmt.Fprintf(out, "Unlocking vault and fetching record by name %q...\n", name)
				}

				// 6. Выводим структурированный результат пользователю
				fmt.Fprintln(out, "\n✔ Decryption successful!")
				fmt.Fprintln(out, "================================================================================")
				fmt.Fprintf(out, "  Secret Name: %s\n", recordName)
				fmt.Fprintln(out, "================================================================================")
				fmt.Fprintf(out, "  Secret Plaintext Payload: %s\n", string(plain.Payload))
				fmt.Fprintln(out, "================================================================================")

				if len(plain.Metadata) > 0 {
					fmt.Fprintln(out, "  Decrypted Metadata:")
					for key, val := range plain.Metadata {
						fmt.Fprintf(out, "    [+] %s : %s\n", key, val)
					}
				} else {
					fmt.Fprintln(out, "  Metadata: <none>")
				}
				fmt.Fprintln(out, "================================================================================")
			})

			return nil
		}),
	}

	// Регистрируем эфемерные флаги
	cmd.Flags().String("id", "", "Lookup secret by its unique UUID")
	cmd.Flags().String("name", "", "Lookup secret by its human-readable name")

	return cmd
}
