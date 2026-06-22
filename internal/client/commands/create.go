// Package commands предоставляет реализации консольных команд Cobra для
// криптографического взаимодействия с хранилищем GophKeeper.
package commands

import (
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

// Максимальный лимит размера файла (10 Мегабайт) для MVP-защиты оперативной памяти.
const maxBinarySize = 10 * 1024 * 1024

var (
	// ErrInvalidSecretType возвращается, если указан неподдерживаемый тип записи.
	ErrInvalidSecretType = errors.New("неподдерживаемый тип секрета: допустимы credentials, text, binary, card")
)

// newCreateCommand конструирует CLI-команду "create" для запечатывания
// и сохранения новой приватной записи в локальном сейфе.
func newCreateCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Запечатать и сохранить новую секретную запись в хранилище",
		Long:  `Шифрует данные алгоритмом XChaCha20-Poly1305 под управлением AccountMasterKey и защищает метаданные от утечек.`,
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			slog.Info("Старт выполнения команды создания и шифрования записи")

			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ошибка проверки ssh-agent")
			}

			// Разбор и валидация входящих аргументов
			flags := cmd.Flags()
			name, _ := flags.GetString("name")
			secretType, _ := flags.GetString("type")
			payloadStr, _ := flags.GetString("payload")
			filePath, _ := flags.GetString("file")
			metaStr, _ := flags.GetString("meta")

			name = strings.TrimSpace(name)
			secretType = strings.ToLower(strings.TrimSpace(secretType))

			if name == "" || secretType == "" {
				return cli.PrintError(out, errors.New("параметры --name и --type обязательны и не могут быть пустыми"), "валидация флагов")
			}

			// Проверка доменного инварианта типов секретов
			switch secretType {
			case "credentials", "text", "binary", "card":
				// Тип валиден
			default:
				return cli.PrintError(out, fmt.Errorf("%w: %q", ErrInvalidSecretType, secretType), "валидация флагов")
			}

			// Извлечение метаданных
			metadataMap, err := parseMetadata(metaStr)
			if err != nil {
				return cli.PrintError(out, err, "параметры метаданных")
			}

			// Извлечение полезной нагрузки (внутри происходит RAM-контроль размера файла)
			finalPayload, err := resolvePayload(secretType, payloadStr, filePath)
			if err != nil {
				return cli.PrintError(out, err, "чтение контента записи")
			}

			// Упаковываем payload и metadata в единый монолитный блок (Защита от Metadata Leakage)
			plainBytes, err := security.PackRecordPlaintext(finalPayload, metadataMap)
			if err != nil {
				security.SecretBytes(finalPayload).Destroy() // Очищаем RAM при сбое
				return cli.PrintError(out, err, "криптографическая упаковка plaintext")
			}

			// Гарантируем уничтожение сырых данных в памяти по выходу из конвейера
			defer func() {
				security.SecretBytes(plainBytes).Destroy()
				security.SecretBytes(finalPayload).Destroy()
				slog.Debug("Сырые байты секрета успешно затерты в оперативной памяти (RAM Hygiene)")
			}()

			// Открываем существующее изолированное рантайм окружение приложения
			app, err := cli.App(ctx)
			if err != nil {
				return cli.PrintError(out, err, "запуск контекста приложения")
			}

			// Сборка зависимостей внутри Composition Root команды
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "подключение к сокету ssh-agent")
			}

			agentClosedChecked := false
			defer func() {
				if !agentClosedChecked {
					if closeErr := agentClient.Close(); closeErr != nil {
						slog.Error("Не удалось закрыть UNIX-сокет агента в defer create", "error", closeErr)
					}
				}
			}()

			secretStore := sqlite.NewSQLiteSecretStore(app.DB())
			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB())
			secretService := service.NewSecretService(secretStore, deviceStore, agentClient)

			// Запускаем криптографический конвейер шифрования записи XChaCha20-Poly1305
			slog.Info("Передача монолитного пакета в криптографический сервис шифрования")
			err = secretService.CreateSecret(ctx, name, secretType, plainBytes)
			if err != nil {
				return cli.PrintError(out, err, "криптографический сбой сохранения записи")
			}

			// Безопасно финализируем соединение с агентом до вывода результатов
			if closeErr := agentClient.Close(); closeErr != nil {
				slog.Error("Не удалось закрыть дескриптор сокета агента при успешном выходе", "error", closeErr)
			}
			agentClosedChecked = true

			payloadOut := CreateResponse{
				Name: name,
				Type: secretType,
			}

			cli.PrintResult(out, payloadOut, func() {
				fmt.Fprintf(out, "Вскрытие мастер-конверта через ssh-agent и запечатывание записи %q...\n", name)
				fmt.Fprintf(out, "✔ Успех! Запись %q [%s] надежно зашифрована и сохранена под AccountMasterKey.\n", name, secretType)
			})

			return nil
		}),
	}

	// Регистрация эфемерных флагов
	cmd.Flags().String("name", "", "Уникальное человекочитаемое имя записи для поиска")
	cmd.Flags().String("type", "", "Тип шифруемого секрета (credentials, text, binary, card)")
	cmd.Flags().String("payload", "", "Текстовое содержимое секрета (пароль, токен, строка)")
	cmd.Flags().String("file", "", "Абсолютный путь к бинарному файлу на диске (только для --type=binary)")
	cmd.Flags().String("meta", "{}", "Дополнительные метаданные в плоском JSON-формате '{\"ключ\":\"значение\"}'")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("type")

	return cmd
}

// parseMetadata парсит и изолирует валидацию строки метаданных
func parseMetadata(metaStr string) (map[string]string, error) {
	var metadataMap map[string]string
	if err := json.Unmarshal([]byte(metaStr), &metadataMap); err != nil {
		slog.Error("Парсинг флага --meta завершился ошибкой синтаксиса", "error", err)
		return nil, fmt.Errorf("неверный формат --meta: параметр обязан быть валидным плоским JSON-объектом вида '{\"ключ\": \"значение\"}'")
	}
	return metadataMap, nil
}

// resolvePayload изолирует чтение и RAM-контроль входящих данных по типу секрета
func resolvePayload(secretType, payloadStr, filePath string) ([]byte, error) {
	if secretType == "binary" {
		if strings.TrimSpace(filePath) == "" {
			return nil, errors.New("флаг --file обязателен, если тип секрета установлен в 'binary'")
		}

		fileInfo, err := os.Stat(filePath)
		if err != nil {
			slog.Error("Не удалось выполнить stat для указанного бинарного файла", "path", filePath, "error", err)
			return nil, fmt.Errorf("файл %q не найден или недоступен", filePath)
		}

		if fileInfo.Size() > maxBinarySize {
			slog.Warn("Заблокирована попытка загрузить файл, превышающий лимиты MVP", "size", fileInfo.Size())
			return nil, fmt.Errorf("размер файла превышает лимит безопасности в 10 Мегабайт (передано: %d байт)", fileInfo.Size())
		}

		finalPayload, err := os.ReadFile(filePath)
		if err != nil {
			slog.Error("Сбой чтения бинарного файла с диска в кучу", "path", filePath, "error", err)
			return nil, fmt.Errorf("ошибка чтения бинарного файла")
		}
		return finalPayload, nil
	}

	if strings.TrimSpace(payloadStr) == "" {
		return nil, fmt.Errorf("флаг --payload не может быть пустым для типа секрета '%s'", secretType)
	}
	return []byte(payloadStr), nil
}
