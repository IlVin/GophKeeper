package commands

import (
	"fmt"
	"os"
	"strings"

	clientconfig "gophkeeper/internal/client/config"
	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/service"
	"gophkeeper/internal/client/sshcheck"

	"github.com/spf13/cobra"
)

func newInitCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize local GophKeeper environment and generate cryptographic root of trust",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			// 1. Проверяем базовое наличие переменной SSH_AUTH_SOCK и доступность агента
			if err := sshcheck.RequireAgent(); err != nil {
				return fmt.Errorf("%w\n\n%s", err, sshcheck.FormatSSHAgentHelp())
			}

			// 2. Загружаем дефолтную конфигурацию приложения из Viper
			cfg, err := cli.AppConfig()
			if err != nil {
				return fmt.Errorf("load app config: %w", err)
			}

			// Запрет повторного init: если файл базы данных уже существует, защищаем данные от перезаписи
			if _, err := os.Stat(cfg.Storage.SQLitePath); err == nil {
				return fmt.Errorf(
					"failed to initialize: GophKeeper environment is already initialized.\n"+
						"Database already exists at: %s\n"+
						"Running 'init' again would overwrite your cryptographic keys and lead to permanent data loss!",
					cfg.Storage.SQLitePath,
				)
			}

			// 3. Подключаемся к ssh-agent, чтобы найти ключ для инициализации контейнера
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return fmt.Errorf("connect to ssh-agent: %w", err)
			}
			defer agentClient.Close()

			// Получаем список всех доступных совместимых ключей Ed25519
			ed25519Keys, err := agentClient.ListED25519()
			if err != nil {
				return fmt.Errorf("failed to find any software ssh-ed25519 keys in ssh-agent: %w", err)
			}

			// Вызываем смарт-селектор для выбора ключа инициализации на основе флага или количества ключей
			targetKeyInfo, err := cli.selectEngineKey(ed25519Keys)
			if err != nil {
				return err // Возвращает чистую структурированную ошибку с диагностикой в stderr
			}

			fmt.Fprintf(out, "Selected root SSH key from agent: %s (%s) [Type: %s]\n",
				targetKeyInfo.Fingerprint,
				targetKeyInfo.Comment,
				targetKeyInfo.Algorithm,
			)

			// 4. Записываем персистентный YAML файл конфигурации на диск, если его нет
			if err := clientconfig.WriteDefaultConfigFile(cfg.App.ConfigFile, cfg); err != nil {
				return fmt.Errorf("write config file: %w", err)
			}

			// 5. Создаем файл SQLite, выставляем права 0600/0700 и накатываем схему миграций goose
			db, err := sqlite.Bootstrap(cfg.Storage.SQLitePath)
			if err != nil {
				return fmt.Errorf("bootstrap sqlite storage: %w", err)
			}
			defer func() {
				_ = db.Close()
			}()

			// 6. Сборка зависимостей «на лету» для изоляции от общего cli.App() контекста
			deviceStore := sqlite.NewSQLiteDeviceStore(db)
			initService := service.NewInitService(deviceStore, agentClient)

			// 7. Запускаем криптографический конвейер вывода ключей и создания конвертов (Envelopes)
			fmt.Fprintln(out, "Generating secure local envelopes (AccountMasterKey, DeviceKEK)...")

			// Передаем дефолтный адрес сервера из конфига
			defaultServer := cli.Viper().GetString("app.default_server")
			if defaultServer == "" {
				defaultServer = "localhost:443" // Санитарный дефолт, если в Viper пусто
			}

			// Извлекаем реальные байты публичного ключа из структуры агента
			rawPublicKeyBytes := targetKeyInfo.PublicKey.Marshal()

			err = initService.ExecuteLocalInit(cmd.Context(), defaultServer, targetKeyInfo.Fingerprint, rawPublicKeyBytes)
			if err != nil {
				return fmt.Errorf("cryptographic initialization failed: %w", err)
			}

			// 8. Фиксируем успех перехода жизненного цикла в статус INITIALIZED
			fmt.Fprintln(out, "\n✔ GophKeeper successfully initialized!")
			fmt.Fprintln(out, "Config file layout written:", cfg.App.ConfigFile)
			fmt.Fprintln(out, "Secure SQLite container created:", cfg.Storage.SQLitePath)
			fmt.Fprintln(out, "Status changed to: INITIALIZED (Local offline operations available)")

			return nil
		},
	}

	// Регистрируем локальный флаг, привязанный исключительно к команде init
	cmd.Flags().String("ssh-fingerprint", "", "SHA256 fingerprint or comment of the key active in ssh-agent")

	// Явно связываем локальный флаг с внутренним Viper селектором CLI-рантайма
	_ = cli.Viper().BindPFlag("app.ssh_key_selector", cmd.Flags().Lookup("ssh-fingerprint"))

	return cmd
}

// selectEngineKey разруливает матрицу условий выбора ключа на основе флага --ssh-fingerprint
func (c *CLI) selectEngineKey(keys []sshagent.SignerInfo) (sshagent.SignerInfo, error) {
	if len(keys) == 0 {
		return sshagent.SignerInfo{}, fmt.Errorf("no software ed25519 keys available in ssh-agent")
	}

	// Извлекаем значение флага из связанного Viper контекста
	selector := strings.TrimSpace(c.v.GetString("app.ssh_key_selector"))

	// Сценарий 1: В агенте ровно один совместимый ключ — используем его без лишних вопросов
	if len(keys) == 1 {
		// Если пользователь все же передал флаг, но он не совпадает с единственным ключом — выбрасываем ошибку
		if selector != "" && keys[0].Fingerprint != selector && keys[0].Comment != selector {
			return sshagent.SignerInfo{}, fmt.Errorf("the specified fingerprint %q was not found in ssh-agent (only %s is available)", selector, keys[0].Fingerprint)
		}
		return keys[0], nil
	}

	// Сценарий 2: В агенте несколько ключей, и пользователь явно указал селектор
	if selector != "" {
		for _, k := range keys {
			if k.Fingerprint == selector || k.Comment == selector {
				return k, nil
			}
		}
		return sshagent.SignerInfo{}, fmt.Errorf("provided --ssh-fingerprint %q matches no active keys in ssh-agent", selector)
	}

	// Сценарий 3: В агенте несколько ключей, а флаг не передан — формируем интерактивную диагностическую карту
	var sb strings.Builder
	sb.WriteString("Multiple compatible Ed25519 keys detected in your ssh-agent.\n")
	sb.WriteString("You must explicitly choose which root key to use via the local '--ssh-fingerprint' flag.\n\n")
	sb.WriteString("Available keys inside agent:\n")

	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("  - Fingerprint: %s\n", k.Fingerprint))
		if k.Comment != "" {
			sb.WriteString(fmt.Sprintf("    Comment:     %s\n", k.Comment))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("Example usage:\n")
	sb.WriteString(fmt.Sprintf("  gophkeeper init --ssh-fingerprint=%s\n", keys[0].Fingerprint))

	return sshagent.SignerInfo{}, fmt.Errorf("%s", sb.String())
}
