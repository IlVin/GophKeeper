// Package commands предоставляет реализации консольных команд Cobra для
// криптографического взаимодействия с хранилищем GophKeeper.
package commands

import (
	"context"
	"encoding/base64"
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

// newGetCommand конструирует CLI-команду "get" для дешифрования,
// проверки целостности и безопасного вывода секретного контента по его ID или имени.
func newGetCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Decrypt and read a private secret from vault by name or ID",
		Long:  `Opens XChaCha20-Poly1305 crypto envelope, verifies integrity via AAD, outputs plaintext to terminal or file.`,
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			slog.Info("Starting secret decryption and reading command")

			// 1. Проверяем базовую доступность SSH-агента в ОС
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ssh-agent check error")
			}

			// Читаем эфемерные флаги поиска записи и выгрузки
			flags := cmd.Flags()
			id, _ := flags.GetString("id")
			name, _ := flags.GetString("name")
			exportPath, _ := flags.GetString("file")

			id = strings.TrimSpace(id)
			name = strings.TrimSpace(name)
			exportPath = strings.TrimSpace(exportPath)

			if id == "" && name == "" {
				return cli.PrintError(out, errors.New("you must specify either --name or --id flag to find the record"), "flag validation")
			}

			// 2. Открываем существующее runtime окружение приложения
			app, err := cli.App(ctx)
			if err != nil {
				return cli.PrintError(out, err, "application context startup")
			}

			// 3. Сборка зависимостей внутри Composition Root команды
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "connect to ssh-agent socket")
			}

			agentClosedChecked := false
			defer func() {
				if !agentClosedChecked {
					if closeErr := agentClient.Close(); closeErr != nil {
						slog.ErrorContext(context.Background(), "Failed to close UNIX agent socket in get defer",
							slog.Any("error", closeErr),
						)
					}
				}
			}()

			secretStore := sqlite.NewSQLiteSecretStore(app.DB())
			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB())
			secretService := service.NewSecretService(secretStore, deviceStore, agentClient)

			// 4. Определение стратегии поиска
			var targetKey string
			var isFindByID bool

			if id != "" {
				targetKey = id
				isFindByID = true
				slog.Debug("Initiating record lookup by unique UUID identifier")
			} else {
				targetKey = name
				isFindByID = false
				slog.Debug("Initiating deterministic record lookup by text name")
			}

			// Вызов криптографического конвейера дешифрования
			recordName, plainBytes, err := secretService.UnsealSecret(ctx, targetKey, isFindByID)
			if err != nil {
				slog.ErrorContext(context.Background(), "Cryptographic pipeline failed to open record envelope",
					slog.Any("error", err),
				)
				return cli.PrintError(out, err, "secret decryption error")
			}

			// Создаем объект безопасности над расшифрованными байтами
			secretBlock := security.SecretBytes(plainBytes)

			// 5. РАСПАКОВКА СТРУКТУРЫ С ЗАЩИТОЙ RAM: Разделяем payload и metadata
			var plain security.RecordPlaintext
			if err := json.Unmarshal(plainBytes, &plain); err != nil {
				secretBlock.Destroy() // Стираем расшифрованные байты при сбое парсинга
				slog.ErrorContext(context.Background(), "Failed to deserialize decrypted monolithic JSON block",
					slog.Any("error", err),
				)
				return cli.PrintError(out, err, "plaintext structure corrupted")
			}

			// Объявляем объекты безопасности над вложенными элементами структуры
			payloadBlock := security.SecretBytes(plain.Payload)

			// Извлекаем тип секрета из сырой записи в СУБД для контроля консольного вывода
			var secretType string
			if isFindByID {
				if rec, _ := secretStore.GetByID(ctx, targetKey); rec != nil {
					secretType = rec.Type
				}
			} else {
				if rec, _ := secretStore.GetByName(ctx, targetKey); rec != nil {
					secretType = rec.Type
				}
			}

			// АППАРАТНАЯ ЗАЩИТА ТЕРМИНАЛА: Запрещаем вывод бинарного типа без указания флага --file или --json
			if secretType == "binary" && exportPath == "" && !cli.JSONOutput {
				secretBlock.Destroy()
				payloadBlock.Destroy()
				statusErr := errors.New("output rejected: secret has type .binary. and cannot be displayed as text. Please specify export path via .--file /path/to/output.")
				return cli.PrintError(out, statusErr, "console protection")
			}

			// Если указан флаг --file — производим принудительную выгрузку сырых байт на диск
			if exportPath != "" {
				slog.Info("Initiating persistent plaintext content export to disk",
					slog.String("path", exportPath),
				)
				if err := os.WriteFile(exportPath, plain.Payload, 0o600); err != nil {
					secretBlock.Destroy()
					payloadBlock.Destroy()
					slog.ErrorContext(context.Background(), "Failed to write decrypted file to disk",
						slog.String("path", exportPath),
						slog.Any("error", err),
					)
					return cli.PrintError(out, err, "file export")
				}
			}

			// Гарантируем тотальное обнуление всех конфиденциальных байт в RAM по выходу из функции
			defer func() {
				secretBlock.Destroy()
				payloadBlock.Destroy()
				for k := range plain.Metadata {
					delete(plain.Metadata, k)
				}
				slog.Debug("Decrypted secret bytes fully wiped from RAM (RAM Hygiene)")
			}()

			// Безопасно финализируем соединение с агентом до вывода результатов на экран
			if closeErr := agentClient.Close(); closeErr != nil {
				slog.ErrorContext(context.Background(), "Failed to close agent socket descriptor on successful exit from get",
					slog.Any("error", closeErr),
				)
			}
			agentClosedChecked = true

			// ФОРМИРОВАНИЕ ПАКЕТА ДЛЯ JSON API (--json)
			var finalPayloadStr string
			if cli.JSONOutput {
				if secretType == "binary" {
					// Для бинарного типа упаковываем данные в безопасный Base64
					finalPayloadStr = base64.StdEncoding.EncodeToString(plain.Payload)
				} else {
					finalPayloadStr = string(plain.Payload)
				}
			}

			payloadOut := GetResponse{
				Name:     recordName,
				Payload:  finalPayloadStr,
				Metadata: plain.Metadata,
			}

			cli.PrintResult(out, payloadOut, func() {
				// 6. Человекочитаемый псевдографический вывод для оператора CLI
				fmt.Fprintln(out, "\n✔ Envelope decryption completed successfully!")
				fmt.Fprintln(out, "================================================================================")
				fmt.Fprintf(out, "  Secret Name  : %s\n", recordName)
				fmt.Fprintf(out, "  Secret Type  : %s\n", secretType)
				fmt.Fprintln(out, "================================================================================")

				if exportPath != "" {
					fmt.Fprintf(out, "  ✔ Content successfully decrypted and saved to disk: %s\n", exportPath)
				} else {
					fmt.Fprintf(out, "  Payload: %s\n", string(plain.Payload))
				}
				fmt.Fprintln(out, "================================================================================")

				if len(plain.Metadata) > 0 {
					fmt.Fprintln(out, "  Decrypted Metadata:")
					for key, val := range plain.Metadata {
						fmt.Fprintf(out, "    [+] %s : %s\n", key, val)
					}
				} else {
					fmt.Fprintln(out, "  Additional metadata: <none>")
				}
				fmt.Fprintln(out, "================================================================================")
			})

			return nil
		}),
	}

	// Регистрация эфемерных флагов поиска и выгрузки
	cmd.Flags().String("id", "", "Find and open record by its UUID identifier")
	cmd.Flags().String("name", "", "Find and open record by its unique text name")
	cmd.Flags().String("file", "", "Absolute path on disk to export decrypted plaintext content")

	return cmd
}
