// Package commands предоставляет реализации консольных команд Cobra для
// криптографического взаимодействия с хранилищем GophKeeper.
package commands

import (
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
		Short: "Удалить зашифрованную запись из локального сейфа по её ID",
		Long:  `Навсегда вычищает строку записи и её крипто-конверт из локальной базы данных SQLite без возможности восстановления.`,
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			slog.Info("Старт выполнения команды деструкции записи")

			// 1. Проверяем базовую доступность SSH-агента в ОС
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ошибка проверки ssh-agent")
			}

			// Читаем эфемерный флаг ID
			flags := cmd.Flags()
			id, _ := flags.GetString("id")
			id = strings.TrimSpace(id)

			if id == "" {
				return cli.PrintError(out, errors.New("параметр --id обязателен и не может быть пустым"), "валидация флагов")
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
						slog.Error("Не удалось закрыть UNIX-сокет агента в defer delete", "error", closeErr)
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

			// 4. Проверяем существование записи перед удалением для вменяемого UX
			slog.Debug("Проверка наличия удаляемого UUID в СУБД SQLite", "id", id)
			record, err := secretStore.GetByID(ctx, id)
			if err != nil {
				return cli.PrintError(out, err, "проверка существования записи в БД")
			}
			if record == nil {
				statusErr := fmt.Errorf("запись с идентификатором %q не найдена в сейфе", id)
				slog.Warn("Попытка удаления несуществующей записи отклонена", "id", id)
				return cli.PrintError(out, statusErr, "ошибка поиска")
			}

			// 5. Вызываем непосредственное удаление в сервисном слое
			slog.Debug("Исполнение низкоуровневой транзакции удаления строки", "id", id)
			err = secretService.DeleteSecret(ctx, id)
			if err != nil {
				return cli.PrintError(out, err, "удаление записи из SQLite")
			}

			// Безопасно финализируем соединение с агентом до вывода результатов
			if closeErr := agentClient.Close(); closeErr != nil {
				slog.Error("Не удалось закрыть дескриптор сокета агента при успешном выходе из delete", "error", closeErr)
			}
			agentClosedChecked = true

			// Формируем структурированный payload для успешного JSON-ответа
			payload := DeleteResultPayload{
				ID:     id,
				Status: "DELETED",
			}

			cli.PrintResult(out, payload, func() {
				fmt.Fprintf(out, "✔ Успех! Запись %q (ID: %s) была безвозвратно удалена из локального сейфа.\n", record.Name, id)
			})

			return nil
		}),
	}

	// Регистрируем обязательный эфемерный флаг удаления
	cmd.Flags().String("id", "", "Уникальный UUID записи для её безвозвратного удаления")
	_ = cmd.MarkFlagRequired("id")

	return cmd
}
