package commands

import (
	"fmt"
	"strings"

	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/service"
	"gophkeeper/internal/client/sshcheck"

	"github.com/spf13/cobra"
)

func newDeleteCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete an encrypted secret from the local vault by its ID",
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			// 1. Проверяем матрицу Preconditions (Инвариант №4: SSH Agent обязателен)
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ssh agent error")
			}

			// Читаем эфемерный флаг ID
			flags := cmd.Flags()
			id, _ := flags.GetString("id")
			id = strings.TrimSpace(id)

			if id == "" {
				return cli.PrintError(out, fmt.Errorf("parameter --id is mandatory and cannot be empty"), "validation failed")
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

			// Криптографический барьер проверки владельца
			if err := secretService.VerifyOwner(cmd.Context()); err != nil {
				return cli.PrintError(out, err, "access denied")
			}

			// 4. Проверяем существование записи перед удалением для вменяемого UX
			record, err := secretStore.GetByID(cmd.Context(), id)
			if err != nil {
				return cli.PrintError(out, err, "failed to check record existence")
			}
			if record == nil {
				return cli.PrintError(out, fmt.Errorf("record with ID %q not found in the vault", id), "not found")
			}

			// 5. Вызываем удаление в сервисе
			err = secretService.DeleteSecret(cmd.Context(), id)
			if err != nil {
				return cli.PrintError(out, err, "failed to delete record")
			}

			// Выводим финальный результат работы команды
			payload := map[string]string{
				"id":     id,
				"status": "DELETED",
			}

			cli.PrintResult(out, payload, func() {
				fmt.Fprintf(out, "✔ Success! Record %q (ID: %s) has been permanently removed from the vault.\n", record.Name, id)
			})

			return nil
		}),
	}

	// Регистрируем эфемерный флаг удаления
	cmd.Flags().String("id", "", "Unique UUID of the record to delete")
	_ = cmd.MarkFlagRequired("id")

	return cmd
}
