// Package commands предоставляет реализации консольных команд Cobra для
// криптографического взаимодействия с хранилищем GophKeeper.
package commands

import (
	"context"
	"fmt"
	"log/slog"
	"text/tabwriter"
	"time"

	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/service"
	"gophkeeper/internal/client/sshcheck"

	"github.com/spf13/cobra"
)

// newListCommand конструирует CLI-команду "list" для безопасного вывода
// легковесного списка метаданных всех запечатанных записей в хранилище.
func newListCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List metadata of all encrypted records in vault",
		Long:  `Extracts IDs, names and types without decrypting or reading secret payload.`,
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			slog.Info("Starting secret metadata listing command")

			// 1. Проверяем базовую доступность SSH-агента в ОС
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ssh-agent check error")
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
						slog.ErrorContext(context.Background(), "Failed to close UNIX agent socket in list defer",
							slog.Any("error", closeErr),
						)
					}
				}
			}()

			secretStore := sqlite.NewSQLiteSecretStore(app.DB())
			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB())
			secretService := service.NewSecretService(secretStore, deviceStore, agentClient)

			// Криптографический барьер Proof of Possession (Проверка владельца)
			if err := secretService.VerifyOwner(ctx); err != nil {
				return cli.PrintError(out, err, "access denied")
			}

			// 4. Получаем список метаданных из сервисного слоя
			slog.Debug("Requesting flat record metadata list from SQLite")
			metadataList, err := secretService.ListSecrets(ctx)
			if err != nil {
				return cli.PrintError(out, err, "record metadata extraction")
			}

			// Безопасно финализируем соединение с агентом до форматирования вывода
			if closeErr := agentClient.Close(); closeErr != nil {
				slog.ErrorContext(context.Background(), "Failed to close agent socket descriptor on successful exit from list",
					slog.Any("error", closeErr),
				)
			}
			agentClosedChecked = true

			// Формируем структурированный payload для успешного JSON-ответа (--json)
			items := make([]ListResponseItem, 0, len(metadataList))
			for _, s := range metadataList {
				items = append(items, ListResponseItem{
					ID:          s.ID,
					Name:        s.Name,
					Type:        s.Type,
					LastUpdated: s.UpdatedAt.Format(time.RFC3339Nano),
				})
			}

			// Выводим финальный результат работы команды
			cli.PrintResult(out, items, func() {
				if len(metadataList) == 0 {
					fmt.Fprintln(out, "Your vault is empty. Use .gophkeeper create. to add records.")
					return
				}

				fmt.Fprintf(out, "Found %d protected records inside vault:\n\n", len(metadataList))

				// Использование tabwriter для красивого колоночного вывода в эмулятор терминала
				w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
				fmt.Fprintln(w, "RECORD ID\tNAME\tTYPE\tLAST UPDATED")
				fmt.Fprintln(w, "---------\t----\t----\t------------")

				for _, m := range metadataList {
					// Приведение UTC временной метки базы к локальному времени пользователя
					localTime := m.UpdatedAt.Local().Format("2006-01-02 15:04:05")
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", m.ID, m.Name, m.Type, localTime)
				}

				// Контроль финализации буфера tabwriter с логированием ошибок вывода
				if flushErr := w.Flush(); flushErr != nil {
					slog.ErrorContext(context.Background(), "Failed to flush tabwriter buffer to terminal output",
						slog.Any("error", flushErr),
					)
				}
			})

			return nil
		}),
	}

	return cmd
}
