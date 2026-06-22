// Package commands предоставляет реализации консольных команд Cobra для
// криптографического взаимодействия с хранилищем GophKeeper.
package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

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
		Short: "Расшифровать и прочитать приватный секрет из сейфа по его имени или ID",
		Long:  `Вскрывает крипто-конверт XChaCha20-Poly1305, верифицирует целостность через AAD и выводит plaintext в терминал.`,
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			slog.Info("Старт выполнения команды дешифрования и чтения секрета")

			// 1. Проверяем базовую доступность SSH-агента в ОС
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ошибка проверки ssh-agent")
			}

			// Читаем эфемерные флаги поиска записи
			flags := cmd.Flags()
			id, _ := flags.GetString("id")
			name, _ := flags.GetString("name")

			if id == "" && name == "" {
				return cli.PrintError(out, errors.New("вы должны указать либо флаг --name, либо флаг --id для поиска записи"), "валидация флагов")
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
						slog.Error("Не удалось закрыть UNIX-сокет агента в defer get", "error", closeErr)
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
				slog.Debug("Инициирован поиск записи по уникальному UUID идентификатору")
			} else {
				targetKey = name
				isFindByID = false
				slog.Debug("Инициирован детерминированный поиск записи по текстовому имени")
			}

			// Вызов криптографического конвейера дешифрования (Возвращает монолитный JSON-блок)
			recordName, plainBytes, err := secretService.UnsealSecret(ctx, targetKey, isFindByID)
			if err != nil {
				slog.Error("Криптографический конвейер не смог вскрыть конверт записи", "error", err)
				return cli.PrintError(out, err, "ошибка дешифрования секрета")
			}

			// Создаем объект безопасности над расшифрованными байтами
			secretBlock := security.SecretBytes(plainBytes)

			// 5. РАСПАКОВКА СТРУКТУРЫ С ЗАЩИТОЙ RAM: Разделяем payload и metadata
			var plain security.RecordPlaintext
			if err := json.Unmarshal(plainBytes, &plain); err != nil {
				secretBlock.Destroy() // Стираем расшифрованные байты при сбое парсинга
				slog.Error("Сбой десериализации расшифрованного монолитного JSON-блока", "error", err)
				return cli.PrintError(out, err, "структура plaintext повреждена")
			}

			// Объявляем объекты безопасности над вложенными элементами структуры
			payloadBlock := security.SecretBytes(plain.Payload)

			// Гарантируем тотальное обнуление всех конфиденциальных байт в RAM по выходу из функции
			defer func() {
				secretBlock.Destroy()
				payloadBlock.Destroy()
				for k := range plain.Metadata {
					delete(plain.Metadata, k) // Ускоряем GC для очистки ссылок метаданных
				}
				slog.Debug("Расшифрованные байты секрета полностью стерты из оперативной памяти (RAM Hygiene)")
			}()

			// Безопасно финализируем соединение с агентом до вывода результатов на экран
			if closeErr := agentClient.Close(); closeErr != nil {
				slog.Error("Не удалось закрыть дескриптор сокета агента при успешном выходе из get", "error", closeErr)
			}
			agentClosedChecked = true

			// Передаем структурированный payload ответа.
			// ВНИМАНИЕ: Для вывода JSON автоматизации мы передаем безопасный слепок
			payloadOut := GetResponse{
				Name:     recordName,
				Payload:  string(plain.Payload), // Копия формируется только на этапе передачи в stdout
				Metadata: plain.Metadata,
			}

			cli.PrintResult(out, payloadOut, func() {
				// 6. Человекочитаемый псевдографический вывод для оператора CLI
				fmt.Fprintln(out, "\n✔ Дешифрование конверта выполнено успешно!")
				fmt.Fprintln(out, "================================================================================")
				fmt.Fprintf(out, "  Имя секрета  : %s\n", recordName)
				fmt.Fprintln(out, "================================================================================")
				fmt.Fprintf(out, "  Полезная нагрузка (Payload): %s\n", string(plain.Payload))
				fmt.Fprintln(out, "================================================================================")

				if len(plain.Metadata) > 0 {
					fmt.Fprintln(out, "  Расшифрованные метаданные:")
					for key, val := range plain.Metadata {
						fmt.Fprintf(out, "    [+] %s : %s\n", key, val)
					}
				} else {
					fmt.Fprintln(out, "  Дополнительные метаданные: <отсутствуют>")
				}
				fmt.Fprintln(out, "================================================================================")
			})

			return nil
		}),
	}

	// Регистрация эфемерных флагов поиска
	cmd.Flags().String("id", "", "Поиск и вскрытие записи по её UUID идентификатору")
	cmd.Flags().String("name", "", "Поиск и вскрытие записи по её уникальному текстовому имени")

	return cmd
}
