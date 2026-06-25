// Package commands предоставляет реализации консольных команд Cobra для
// криптографического взаимодействия с хранилищем GophKeeper.
package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/service"
	"gophkeeper/internal/client/sshcheck"

	"github.com/spf13/cobra"
)

// DeleteResultPayload определяет структуру успешного ответа для JSON-конверта автоматизации.
type DeleteResultPayload struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// newDeleteCommand конструирует CLI-команду "delete" для безвозвратного
// удаления зашифрованной записи из локального сейфа по её UUID.
func newDeleteCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete encrypted record from local vault by its ID",
		Long:  `Permanently removes the record row and its crypto envelope from the local SQLite database.`,
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			slog.Info("Starting record destruction command")

			// 1. Проверяем базовую доступность SSH-агента в ОС
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ssh-agent check error")
			}

			// Читаем эфемерный флаг ID
			flags := cmd.Flags()
			id, _ := flags.GetString("id")
			id = strings.TrimSpace(id)

			if id == "" {
				return cli.PrintError(out, errors.New("--id parameter is required and cannot be empty"), "flag validation")
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
						slog.ErrorContext(context.Background(), "Failed to close UNIX agent socket in delete defer",
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

			// 4. Проверяем существование записи перед удалением для вменяемого UX
			slog.Debug("Checking existence of deleting UUID in SQLite DB",
				slog.String("id", id),
			)
			record, err := secretStore.GetByID(ctx, id)
			if err != nil {
				return cli.PrintError(out, err, "checking record existence in DB")
			}
			if record == nil {
				statusErr := fmt.Errorf("record with identifier %q not found in vault", id)
				slog.Warn("Attempt to delete non-existent record rejected",
					slog.String("id", id),
				)
				return cli.PrintError(out, statusErr, "search error")
			}

			// 5. Вызываем непосредственное удаление в сервисном слое
			slog.Debug("Executing low-level row deletion transaction",
				slog.String("id", id),
			)
			err = secretService.DeleteSecret(ctx, id)
			if err != nil {
				return cli.PrintError(out, err, "delete record from SQLite")
			}

			// Безопасно финализируем соединение с агентом до вывода результатов
			if closeErr := agentClient.Close(); closeErr != nil {
				slog.ErrorContext(context.Background(), "Failed to close agent socket descriptor on successful exit from delete",
					slog.Any("error", closeErr),
				)
			}
			agentClosedChecked = true

			// Формируем структурированный payload для успешного JSON-ответа
			payload := DeleteResultPayload{
				ID:     id,
				Status: "DELETED",
			}

			cli.PrintResult(out, payload, func() {
				fmt.Fprintf(out, "✔ SUCCESS! Record %q (ID: %s) was permanently deleted from local vault.\n", record.Name, id)
			})

			return nil
		}),
	}

	// Регистрируем обязательный эфемерный флаг удаления
	cmd.Flags().String("id", "", "Unique UUID of the record for permanent deletion")
	_ = cmd.MarkFlagRequired("id")

	return cmd
}
