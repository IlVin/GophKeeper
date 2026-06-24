// Package commands предоставляет реализации консольных команд Cobra для
// криптографического взаимодействия с хранилищем GophKeeper.
package commands

import (
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
		Short: "Вывести список метаданных всех зашифрованных записей в сейфе",
		Long:  `Извлекает идентификаторы, имена и типы записей без расшифровки и чтения их секретного содержимого (payload).`,
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			slog.Info("Старт выполнения команды листинга метаданных секретов")

			// 1. Проверяем базовую доступность SSH-агента в ОС
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ошибка проверки ssh-agent")
			}

			// 2. Открываем существующее runtime окружение приложения
			app, err := cli.App(ctx)
			if err != nil {
				return cli.PrintError(out, err, "запуск контекста приложения")
			}

			// 3. Сборка зависимостей внутри Composition Root команды
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "подключение к сокету ssh-agent")
			}

			agentClosedChecked := false
			defer func() {
				if !agentClosedChecked {
					if closeErr := agentClient.Close(); closeErr != nil {
						slog.Error("Не удалось закрыть UNIX-сокет агента в defer list", "error", closeErr)
					}
				}
			}()

			secretStore := sqlite.NewSQLiteSecretStore(app.DB())
			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB())
			secretService := service.NewSecretService(secretStore, deviceStore, agentClient)

			// Криптографический барьер Proof of Possession (Проверка владельца)
			if err := secretService.VerifyOwner(ctx); err != nil {
				return cli.PrintError(out, err, "отказ в доступе")
			}

			// 4. Получаем список метаданных из сервисного слоя
			slog.Debug("Запрос плоского списка метаданных записей из SQLite")
			metadataList, err := secretService.ListSecrets(ctx)
			if err != nil {
				return cli.PrintError(out, err, "извлечение метаданных записей")
			}

			// Безопасно финализируем соединение с агентом до форматирования вывода
			if closeErr := agentClient.Close(); closeErr != nil {
				slog.Error("Не удалось закрыть дескриптор сокета агента при успешном выходе из list", "error", closeErr)
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
					fmt.Fprintln(out, "Ваш сейф пуст. Используйте команду 'gophkeeper create' для добавления записей.")
					return
				}

				fmt.Fprintf(out, "Обнаружено %d защищенных записей внутри сейфа:\n\n", len(metadataList))

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
					slog.Error("Сбой сброса буфера tabwriter в поток вывода терминала", "error", flushErr)
				}
			})

			return nil
		}),
	}

	return cmd
}
