// Package commands предоставляет реализации консольных команд Cobra для
// криптографического взаимодействия с хранилищем GophKeeper.
package commands

import (
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
		Short: "Расшифровать и прочитать приватный секрет из сейфа по его имени или ID",
		Long:  `Вскрывает крипто-конверт XChaCha20-Poly1305, верифицирует целостность через AAD, выводит plaintext в терминал или выгружает в файл.`,
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			slog.Info("Старт выполнения команды дешифрования и чтения секрета")

			// 1. Проверяем базовую доступность SSH-агента в ОС
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ошибка проверки ssh-agent")
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

			// Вызов криптографического конвейера дешифрования
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
				statusErr := errors.New("отказ вывода: секрет имеет тип 'binary' и не может быть отображен в терминале в виде текста. Пожалуйста, укажите путь выгрузки через флаг '--file /path/to/output'")
				return cli.PrintError(out, statusErr, "защита консоли")
			}

			// Если указан флаг --file — производим принудительную выгрузку сырых байт на диск
			if exportPath != "" {
				slog.Info("Инициирована персистентная выгрузка plaintext контента на диск", "path", exportPath)
				if err := os.WriteFile(exportPath, plain.Payload, 0o600); err != nil {
					secretBlock.Destroy()
					payloadBlock.Destroy()
					slog.Error("Сбой записи расшифрованного файла на диск", "path", exportPath, "error", err)
					return cli.PrintError(out, err, "экспорт в файл")
				}
			}

			// Гарантируем тотальное обнуление всех конфиденциальных байт в RAM по выходу из функции
			defer func() {
				secretBlock.Destroy()
				payloadBlock.Destroy()
				for k := range plain.Metadata {
					delete(plain.Metadata, k)
				}
				slog.Debug("Расшифрованные байты секрета полностью стерты из оперативной памяти (RAM Hygiene)")
			}()

			// Безопасно финализируем соединение с агентом до вывода результатов на экран
			if closeErr := agentClient.Close(); closeErr != nil {
				slog.Error("Не удалось закрыть дескриптор сокета агента при успешном выходе из get", "error", closeErr)
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
				fmt.Fprintln(out, "\n✔ Дешифрование конверта выполнено успешно!")
				fmt.Fprintln(out, "================================================================================")
				fmt.Fprintf(out, "  Имя секрета  : %s\n", recordName)
				fmt.Fprintf(out, "  Тип секрета  : %s\n", secretType)
				fmt.Fprintln(out, "================================================================================")

				if exportPath != "" {
					fmt.Fprintf(out, "  ✔ Контент успешно расшифрован и сохранен на диск: %s\n", exportPath)
				} else {
					fmt.Fprintf(out, "  Полезная нагрузка (Payload): %s\n", string(plain.Payload))
				}
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

	// Регистрация эфемерных флагов поиска и выгрузки
	cmd.Flags().String("id", "", "Поиск и вскрытие записи по её UUID идентификатору")
	cmd.Flags().String("name", "", "Поиск и вскрытие записи по её уникальному текстовому имени")
	cmd.Flags().String("file", "", "Абсолютный путь на диске для выгрузки расшифрованного plaintext контента")

	return cmd
}
