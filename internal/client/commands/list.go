package commands

import (
	"fmt"
	"text/tabwriter"

	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/service"
	"gophkeeper/internal/client/sshcheck"

	"github.com/spf13/cobra"
)

func newListCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all encrypted secret metadata stored in the local vault",
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			// 1. Проверяем матрицу Preconditions (Инвариант №4: SSH Agent обязателен для операционных команд)
			if err := sshcheck.RequireAgent(); err != nil {
				return fmt.Errorf("%w\n\n%s", err, sshcheck.FormatSSHAgentHelp())
			}

			// 2. Открываем существующее runtime окружение приложения
			app, err := cli.App(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to open application runtime: %w", err)
			}

			// 3. Сборка зависимостей «на лету» внутри Composition Root
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return fmt.Errorf("connect to ssh-agent: %w", err)
			}
			defer agentClient.Close()

			secretStore := sqlite.NewSQLiteSecretStore(app.DB)
			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB)
			secretService := service.NewSecretService(secretStore, deviceStore, agentClient)

			// Криптографический барьер проверки владельца
			if err := secretService.VerifyOwner(cmd.Context()); err != nil {
				return err
			}

			// 4. Получаем список метаданных из сервисного слоя
			metadataList, err := secretService.ListSecrets(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to retrieve records list: %w", err)
			}

			if len(metadataList) == 0 {
				fmt.Fprintln(out, "The vault is currently empty. Use 'gophkeeper create' to add secrets.")
				return nil
			}

			fmt.Fprintf(out, "Found %d secure records inside the vault:\n\n", len(metadataList))

			// Используем tabwriter для красивого колоночного вывода в терминал
			w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "RECORD ID\tNAME\tTYPE\tLAST UPDATED")
			fmt.Fprintln(w, "---------\t----\t----\t------------")

			for _, m := range metadataList {
				// Форматируем время в локальную строку
				localTime := m.UpdatedAt.Local().Format("2006-01-02 15:04:05")
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", m.ID, m.Name, m.Type, localTime)
			}
			w.Flush()

			return nil
		}),
	}

	return cmd
}
