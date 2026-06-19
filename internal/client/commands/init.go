package commands

import (
	"fmt"
	"os"

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

			// 1. Проверяем базовое наличие переменной SSH_AUTH_SOCK
			if err := sshcheck.RequireAgent(); err != nil {
				return fmt.Errorf("%w\n\n%s", err, sshcheck.FormatSSHAgentHelp())
			}

			// 2. Загружаем дефолтную конфигурацию приложения из Viper
			cfg, err := cli.AppConfig()
			if err != nil {
				return fmt.Errorf("load app config: %w", err)
			}

			// Запрет повторного init
			// Если файл базы данных уже существует, выбрасываем ошибку и защищаем данные
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

			// Получаем список всех доступных ключей Ed25519
			ed25519Keys, err := agentClient.ListED25519()
			if err != nil {
				return fmt.Errorf("failed to find any software ssh-ed25519 keys in ssh-agent: %w", err)
			}

			// Используем первый доступный детерминированный ключ Ed25519 как Root of Trust
			targetKeyInfo := ed25519Keys[0]
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

			// 6. Сборка зависимостей «на лету» для изоляции от cli.App() контекста
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

	return cmd
}
