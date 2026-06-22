package commands

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	clientconfig "gophkeeper/internal/client/config"
	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/service"
	"gophkeeper/internal/client/sshcheck"

	"github.com/spf13/cobra"
)

// InitResultPayload определяет структуру успешного вывода для JSON-конверта автоматизации.
type InitResultPayload struct {
	ConfigFile string `json:"config_file"`
	SQLitePath string `json:"sqlite_path"`
	Status     string `json:"status"`
}

// newInitCommand конструирует CLI-команду "init" для первичной локальной
// инициализации криптографического окружения GophKeeper.
func newInitCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Инициализировать локальное окружение и криптографический корень доверия",
		Long:  `Создает защищенный контейнер SQLite, генерирует локальные конверты AccountMasterKey и DeviceKEK под управлением ключа ssh-agent.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			slog.Info("Запуск конвейера локальной инициализации контейнера GophKeeper")

			// 1. Проверяем доступность SSH-агента в операционной системе
			if err := sshcheck.RequireAgent(); err != nil {
				slog.Error("Локальная инициализация отклонена: ssh-agent недоступен")
				return cli.PrintError(out, err, "ошибка проверки ssh-agent")
			}

			// 2. Читаем дефолтную конфигурацию приложения из Viper
			cfg, err := cli.AppConfig()
			if err != nil {
				slog.Error("Не удалось прочитать параметры конфигурации для init", "error", err)
				return cli.PrintError(out, err, "загрузка конфигурации")
			}

			sqlitePath := cfg.Storage().SQLitePath()
			configPath := cfg.App().ConfigFile()

			// Запрет повторного init: защищаем существующие крипто-конверты от перезаписи
			if _, err := os.Stat(sqlitePath); err == nil {
				statusErr := fmt.Errorf("среда GophKeeper уже инициализирована. Контейнер СУБД присутствует по пути: %s. Повторный запуск init уничтожит ваши ключи деривации", sqlitePath)
				slog.Warn("Попытка повторной инициализации поверх живой базы данных заблокирована")
				return cli.PrintError(out, statusErr, "ошибка жизненного цикла")
			}

			// 3. Подключаемся к ssh-agent для сканирования Ed25519 ключей деривации
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "подключение к сокету ssh-agent")
			}
			defer agentClient.Close()

			ed25519Keys, err := agentClient.ListED25519()
			if err != nil {
				slog.Error("В ssh-agent не обнаружено детерминированных программных ключей ed25519")
				return cli.PrintError(out, err, "сканирование ключей в ssh-agent")
			}

			// Запуск смарт-селектора для выбора корневого ключа
			targetKeyInfo, err := cli.selectEngineKey(ed25519Keys)
			if err != nil {
				return cli.PrintError(out, err, "селектор корневого ключа")
			}

			slog.Info("Для инициализации контейнера успешно выбран корень доверия", "fingerprint", targetKeyInfo.Fingerprint)

			// 4. Записываем персистентный YAML файл конфигурации на диск, если его нет
			if err := clientconfig.WriteDefaultConfigFile(configPath, cfg); err != nil {
				return cli.PrintError(out, err, "запись конфигурационного файла")
			}

			// 5. Создаем файл SQLite, выставляем права 0600/0700 и накатываем схему миграций goose
			slog.Debug("Запуск процедуры bootstrap и миграции базы данных")
			db, err := sqlite.Bootstrap(sqlitePath)
			if err != nil {
				return cli.PrintError(out, err, "разворачивание структуры СУБД")
			}

			dbClosedCheked := false
			defer func() {
				if !dbClosedCheked {
					if closeErr := db.Close(); closeErr != nil {
						slog.Error("Не удалось закрыть дескриптор базы данных в defer init", "error", closeErr)
					}
				}
			}()

			// 6. Сборка зависимостей «на лету» внутри Composition Root команды
			deviceStore := sqlite.NewSQLiteDeviceStore(db)
			initService := service.NewInitService(deviceStore, agentClient)

			// 7. Запускаем криптографический конвейер вывода ключей и создания конвертов (Envelopes)
			slog.Info("Старт генерации защищенных локальных конвертов (AccountMasterKey, DeviceKEK)")
			defaultServer := cli.Viper().GetString("app.default_server")
			if strings.TrimSpace(defaultServer) == "" {
				defaultServer = "localhost:443"
			}

			rawPublicKeyBytes := targetKeyInfo.PublicKey.Marshal()

			err = initService.ExecuteLocalInit(cmd.Context(), defaultServer, targetKeyInfo.Fingerprint, rawPublicKeyBytes)
			if err != nil {
				slog.Error("Криптографический конвейер инициализации завершился аварийно", "error", err)
				return cli.PrintError(out, err, "криптографическая инициализация")
			}

			// Проверяем явное закрытие пула до вывода результатов
			if closeErr := db.Close(); closeErr != nil {
				slog.Error("Не удалось безопасно зафиксировать WAL-сессию при закрытии пула СУБД", "error", closeErr)
				return cli.PrintError(out, closeErr, "финализация СУБД")
			}
			dbClosedCheked = true

			// 8. Формируем структурированный payload для успешного вывода
			payload := InitResultPayload{
				ConfigFile: configPath,
				SQLitePath: sqlitePath,
				Status:     "INITIALIZED",
			}

			cli.PrintResult(out, payload, func() {
				fmt.Fprintf(out, "Выбран корневой SSH-ключ из агента: %s (%s)\n", targetKeyInfo.Fingerprint, targetKeyInfo.Comment)
				fmt.Fprintln(out, "Генерация защищенных локальных конвертов завершена успешно.")
				fmt.Fprintln(out, "\n✔ Окружение GophKeeper успешно инициализировано!")
				fmt.Fprintln(out, "Конфигурационный YAML-файл записан:", configPath)
				fmt.Fprintln(out, "Зашифрованный SQLite контейнер создан:", sqlitePath)
				fmt.Fprintln(out, "Текущий статус жизненного цикла среды: INITIALIZED (Доступен оффлайн-режим)")
			})

			return nil
		},
	}

	// Регистрируем локальный флаг, привязанный исключительно к контексту команды init
	cmd.Flags().String("ssh-fingerprint", "", "SHA256 фингерпринт или комментарий целевого ключа в ssh-agent")

	// Связываем локальный флаг с внутренним Viper селектором CLI-рантайма
	_ = cli.Viper().BindPFlag("app.ssh_key_selector", cmd.Flags().Lookup("ssh-fingerprint"))

	return cmd
}

// selectEngineKey разрешает матрицу условий выбора ключа деривации на основе флага --ssh-fingerprint.
func (c *CLI) selectEngineKey(keys []sshagent.SignerInfo) (sshagent.SignerInfo, error) {
	if len(keys) == 0 {
		return sshagent.SignerInfo{}, errors.New("в ssh-agent отсутствуют доступные программные ed25519 ключи")
	}

	selector := strings.TrimSpace(c.v.GetString("app.ssh_key_selector"))

	// Сценарий 1: В агенте присутствует ровно один совместимый ключ — выбираем его автоматически
	if len(keys) == 1 {
		if selector != "" && keys[0].Fingerprint != selector && keys[0].Comment != selector {
			return sshagent.SignerInfo{}, fmt.Errorf("указанный фингерпринт %q не найден в ssh-agent (доступен только %s)", selector, keys[0].Fingerprint)
		}
		return keys[0], nil
	}

	// Сценарий 2: В агенте несколько ключей, и пользователь явно передал селектор
	if selector != "" {
		for _, k := range keys {
			if k.Fingerprint == selector || k.Comment == selector {
				return k, nil
			}
		}
		return sshagent.SignerInfo{}, fmt.Errorf("указанный флаг --ssh-fingerprint %q не совпал ни с одним активным ключом в ssh-agent", selector)
	}

	// Сценарий 3: В агенте несколько ключей, а флаг не передан — формируем интерактивную диагностическую карту
	var sb strings.Builder
	sb.WriteString("В вашем ssh-agent обнаружено несколько совместимых ключей Ed25519.\n")
	sb.WriteString("Вы должны явно указать корневой ключ с помощью локального флага '--ssh-fingerprint'.\n\n")
	sb.WriteString("Список доступных ключей внутри агента:\n")

	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("  - Фингерпринт: %s\n", k.Fingerprint))
		if k.Comment != "" {
			sb.WriteString(fmt.Sprintf("    Комментарий: %s\n", k.Comment))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("Пример запуска команды:\n")
	sb.WriteString(fmt.Sprintf("  gophkeeper init --ssh-fingerprint=%s\n", keys[0].Fingerprint))

	return sshagent.SignerInfo{}, errors.New(sb.String())
}
