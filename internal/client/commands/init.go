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
		Short: "Initialize local environment and cryptographic root of trust",
		Long:  `Creates a secure SQLite container, generates local AccountMasterKey and DeviceKEK envelopes under ssh-agent key control.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			slog.Info("Starting local GophKeeper container initialization pipeline")

			// 1. Проверяем доступность SSH-агента в операционной системе
			if err := sshcheck.RequireAgent(); err != nil {
				slog.Error("Local initialization rejected: ssh-agent unavailable")
				return cli.PrintError(out, err, "ssh-agent check error")
			}

			// 2. Читаем дефолтную конфигурацию приложения из Viper
			cfg, err := cli.AppConfig()
			if err != nil {
				slog.Error("Failed to read config params for init", "error", err)
				return cli.PrintError(out, err, "config loading")
			}

			sqlitePath := cfg.Storage().SQLitePath()
			configPath := cfg.App().ConfigFile()

			// Запрет повторного init: защищаем существующие крипто-конверты от перезаписи
			if _, err := os.Stat(sqlitePath); err == nil {
				statusErr := fmt.Errorf("GophKeeper environment already initialized. DB container exists at: %s. Re-running init will destroy your derivation keys", sqlitePath)
				slog.Warn("Attempt to re-initialize over live database blocked")
				return cli.PrintError(out, statusErr, "lifecycle error")
			}

			// 3. Подключаемся к ssh-agent для сканирования Ed25519 ключей деривации
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "connect to ssh-agent socket")
			}
			defer agentClient.Close()

			ed25519Keys, err := agentClient.ListED25519()
			if err != nil {
				slog.Error("No deterministic software ed25519 keys found in ssh-agent")
				return cli.PrintError(out, err, "scanning keys in ssh-agent")
			}

			// Запуск смарт-селектора для выбора корневого ключа
			targetKeyInfo, err := cli.selectEngineKey(ed25519Keys)
			if err != nil {
				return cli.PrintError(out, err, "root key selector")
			}

			slog.Info("Root of trust successfully selected for container initialization", "fingerprint", targetKeyInfo.Fingerprint)

			// 4. Записываем персистентный YAML файл конфигурации на диск, если его нет
			if err := clientconfig.WriteDefaultConfigFile(configPath, cfg); err != nil {
				return cli.PrintError(out, err, "config file write")
			}

			// 5. Создаем файл SQLite, выставляем права 0600/0700 и накатываем схему миграций goose
			slog.Debug("Starting database bootstrap and migration procedure")
			db, err := sqlite.Bootstrap(sqlitePath)
			if err != nil {
				return cli.PrintError(out, err, "database structure deployment")
			}

			dbClosedCheked := false
			defer func() {
				if !dbClosedCheked {
					if closeErr := db.Close(); closeErr != nil {
						slog.Error("Failed to close database descriptor in init defer", "error", closeErr)
					}
				}
			}()

			// 6. Сборка зависимостей «на лету» внутри Composition Root команды
			deviceStore := sqlite.NewSQLiteDeviceStore(db)
			initService := service.NewInitService(deviceStore, agentClient)

			// 7. Запускаем криптографический конвейер вывода ключей и создания конвертов (Envelopes)
			slog.Info("Starting generation of secure local envelopes (AccountMasterKey, DeviceKEK)")
			defaultServer := cli.Viper().GetString("app.default_server")
			if strings.TrimSpace(defaultServer) == "" {
				defaultServer = "localhost:443"
			}

			rawPublicKeyBytes := targetKeyInfo.PublicKey.Marshal()

			err = initService.ExecuteLocalInit(cmd.Context(), defaultServer, targetKeyInfo.Fingerprint, rawPublicKeyBytes)
			if err != nil {
				slog.Error("Cryptographic initialization pipeline crashed", "error", err)
				return cli.PrintError(out, err, "cryptographic initialization")
			}

			// Проверяем явное закрытие пула до вывода результатов
			if closeErr := db.Close(); closeErr != nil {
				slog.Error("Failed to safely commit WAL session during DB pool close", "error", closeErr)
				return cli.PrintError(out, closeErr, "database finalization")
			}
			dbClosedCheked = true

			// 8. Формируем структурированный payload для успешного вывода
			payload := InitResultPayload{
				ConfigFile: configPath,
				SQLitePath: sqlitePath,
				Status:     "INITIALIZED",
			}

			cli.PrintResult(out, payload, func() {
				fmt.Fprintf(out, "Selected root SSH key from agent: %s (%s)\n", targetKeyInfo.Fingerprint, targetKeyInfo.Comment)
				fmt.Fprintln(out, "Secure local envelope generation completed successfully.")
				fmt.Fprintln(out, "\n✔ GophKeeper environment successfully initialized!")
				fmt.Fprintln(out, "Configuration YAML file written:", configPath)
				fmt.Fprintln(out, "Encrypted SQLite container created:", sqlitePath)
				fmt.Fprintln(out, "Current environment lifecycle status: INITIALIZED (Offline mode available)")
			})

			return nil
		},
	}

	// Регистрируем локальный флаг, привязанный исключительно к контексту команды init
	cmd.Flags().String("ssh-fingerprint", "", "SHA256 fingerprint or comment of target key in ssh-agent")

	// Связываем локальный флаг с внутренним Viper селектором CLI-рантайма
	_ = cli.Viper().BindPFlag("app.ssh_key_selector", cmd.Flags().Lookup("ssh-fingerprint"))

	return cmd
}

// selectEngineKey разрешает матрицу условий выбора ключа деривации на основе флага --ssh-fingerprint.
func (c *CLI) selectEngineKey(keys []sshagent.SignerInfo) (sshagent.SignerInfo, error) {
	if len(keys) == 0 {
		return sshagent.SignerInfo{}, errors.New("no available software ed25519 keys in ssh-agent")
	}

	selector := strings.TrimSpace(c.v.GetString("app.ssh_key_selector"))

	// Сценарий 1: В агенте присутствует ровно один совместимый ключ — выбираем его автоматически
	if len(keys) == 1 {
		if selector != "" && keys[0].Fingerprint != selector && keys[0].Comment != selector {
			return sshagent.SignerInfo{}, fmt.Errorf("specified fingerprint %q not found in ssh-agent (only %s available)", selector, keys[0].Fingerprint)
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
		return sshagent.SignerInfo{}, fmt.Errorf("specified --ssh-fingerprint %q did not match any active key in ssh-agent", selector)
	}

	// Сценарий 3: В агенте несколько ключей, а флаг не передан — формируем интерактивную диагностическую карту
	var sb strings.Builder
	sb.WriteString("Multiple compatible Ed25519 keys found in your ssh-agent.\n")
	sb.WriteString("You must explicitly specify the root key using the .--ssh-fingerprint. flag..\n\n")
	sb.WriteString("List of available keys in agent:\n")

	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("  - Fingerprint: %s\n", k.Fingerprint))
		if k.Comment != "" {
			sb.WriteString(fmt.Sprintf("    Comment: %s\n", k.Comment))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("Example command:\n")
	sb.WriteString(fmt.Sprintf("  gophkeeper init --ssh-fingerprint=%s\n", keys[0].Fingerprint))

	return sshagent.SignerInfo{}, errors.New(sb.String())
}
