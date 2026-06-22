package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	clientapp "gophkeeper/internal/client/app"
	clientconfig "gophkeeper/internal/client/config"
	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/client/sshcheck"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

type CLI struct {
	v *viper.Viper

	configOnce sync.Once
	config     clientconfig.Config
	configErr  error

	appMu      sync.Mutex
	app        *clientapp.App
	appErr     error
	JSONOutput bool
}

func NewCLI(v *viper.Viper) *CLI {
	return &CLI{v: v}
}

func NewRootCommand(v *viper.Viper) (*cobra.Command, error) {
	return NewCLI(v).NewRootCommand()
}

func (c *CLI) NewRootCommand() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:           "gophkeeper",
		Short:         "GophKeeper CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	if err := c.bindPersistentFlags(cmd); err != nil {
		return nil, err
	}

	c.addCommands(cmd)

	return cmd, nil
}

func (c *CLI) Viper() *viper.Viper {
	return c.v
}

func (c *CLI) AppConfig() (clientconfig.Config, error) {
	c.configOnce.Do(func() {
		if err := clientconfig.ReadConfigFile(c.v); err != nil {
			c.configErr = fmt.Errorf("read config file: %w", err)
			return
		}

		cfg, err := clientconfig.LoadFromViper(c.v)
		if err != nil {
			c.configErr = fmt.Errorf("load config from viper: %w", err)
			return
		}

		c.config = cfg
	})

	if c.configErr != nil {
		return clientconfig.Config{}, c.configErr
	}

	return c.config, nil
}

func (c *CLI) DBPath() (string, error) {
	cfg, err := c.AppConfig()
	if err != nil {
		return "", err
	}

	return cfg.Storage.SQLitePath, nil
}

func (c *CLI) App(ctx context.Context) (*clientapp.App, error) {
	c.appMu.Lock()
	defer c.appMu.Unlock()

	if c.app != nil {
		return c.app, nil
	}

	cfg, err := c.AppConfig()
	if err != nil {
		c.appErr = err
		return nil, err
	}

	app, err := clientapp.New(ctx, cfg)
	if err != nil {
		c.appErr = fmt.Errorf("initialize app: %w", err)
		return nil, c.appErr
	}

	c.app = app
	c.appErr = nil

	return c.app, nil
}

func (c *CLI) Close() error {
	c.appMu.Lock()
	defer c.appMu.Unlock()

	if c.app == nil {
		return nil
	}

	err := clientapp.Shutdown(c.app)
	c.app = nil
	c.appErr = nil

	if err != nil {
		return fmt.Errorf("shutdown app: %w", err)
	}

	return nil
}

func (c *CLI) withApp(
	run func(cmd *cobra.Command, args []string, app *clientapp.App) error,
) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		app, err := c.App(cmd.Context())
		if err != nil {
			return err
		}

		defer func() {
			_ = c.Close()
		}()

		return run(cmd, args, app)
	}
}

func (c *CLI) bindPersistentFlags(cmd *cobra.Command) error {
	cmd.PersistentFlags().String("config", "", "path to config file")
	cmd.PersistentFlags().String("sqlite-path", "", "path to local SQLite database")
	cmd.PersistentFlags().BoolVar(&c.JSONOutput, "json", false, "Output results as a clean JSON object for automation and E2E testing")

	if err := c.v.BindPFlag("app.config_file", cmd.PersistentFlags().Lookup("config")); err != nil {
		return fmt.Errorf("bind flag config: %w", err)
	}

	if err := c.v.BindPFlag("storage.sqlite_path", cmd.PersistentFlags().Lookup("sqlite-path")); err != nil {
		return fmt.Errorf("bind flag sqlite-path: %w", err)
	}

	return nil
}

func (c *CLI) addCommands(cmd *cobra.Command) {
	cmd.AddCommand(
		newInitCommand(c),
		newRegisterCommand(c),
		newCreateCommand(c),
		newListCommand(c),
		newGetCommand(c),
		newDeleteCommand(c),
		newSyncCommand(c),
	)
}

func trim(s string) string {
	return strings.TrimSpace(s)
}

func (c *CLI) withSSHAgent(
	run func(cmd *cobra.Command, args []string) error,
) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := sshcheck.RequireAgent(); err != nil {
			return fmt.Errorf("%w\n\n%s", err, sshcheck.FormatSSHAgentHelp())
		}

		return run(cmd, args)
	}
}

// withOwnerCheck проверяет, что контейнер инициализирован и ключ инициализации активен в ssh-agent
func (c *CLI) withOwnerCheck(
	run func(cmd *cobra.Command, args []string) error,
) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		// 1. Проверяем базовую доступность SSH-агента (Инвариант №4)
		if err := sshcheck.RequireAgent(); err != nil {
			return fmt.Errorf("%w\n\n%s", err, sshcheck.FormatSSHAgentHelp())
		}

		// 2. Читаем локальное состояние из базы данных через App контекст
		state, err := c.deviceStoreReader(cmd.Context())
		if err != nil {
			// Если БД не инициализирована, возвращаем ошибку "run init first"
			return err
		}

		// 3. Извлекаем публичный ключ, с которым инитилась БД, и считаем его фингерпринт
		dbPubKey, err := ssh.ParsePublicKey(state.SshPublicKey)
		if err != nil {
			return fmt.Errorf("database corruption: failed to parse saved public key: %w", err)
		}
		expectedFingerprint := sshagent.FingerprintSHA256(dbPubKey)

		// 4. Подключаемся к агенту и проверяем, загружен ли этот конкретный ключ
		agentClient, err := sshagent.NewFromEnv()
		if err != nil {
			return fmt.Errorf("connect to ssh-agent: %w", err)
		}
		defer agentClient.Close()

		// Ищем ключ по фингерпринту инициализации
		_, err = agentClient.FindED25519ByFingerprint(expectedFingerprint)
		if err != nil {
			return fmt.Errorf(
				"access denied: root cryptographic key used during 'init' is missing from your ssh-agent.\n"+
					"Expected fingerprint: %s\n"+
					"Please load the correct key via 'ssh-add'",
				expectedFingerprint,
			)
		}

		// Если барьер пройден, передаем управление оригинальной логике команды
		return run(cmd, args)
	}
}

// Вспомогательный хелпер для безопасного извлечения состояния до полной сборки cli.App
func (c *CLI) deviceStoreReader(ctx context.Context) (*repository.LocalDeviceState, error) {
	cfg, err := c.AppConfig()
	if err != nil {
		return nil, err
	}

	// Открываем легковесное соединение чисто под чтение статуса
	db, err := sqlite.Open(cfg.Storage.SQLitePath)
	if err != nil {
		return nil, fmt.Errorf("client environment is not initialized: please run 'gophkeeper init' first")
	}
	defer db.Close()

	deviceStore := sqlite.NewSQLiteDeviceStore(db)
	return deviceStore.ReadDeviceState(ctx)
}

// PrintResult автоматически определяет формат (JSON API или текст) для успешного вывода.
// Если включен JSON, он заворачивает payload в CLIResponse{Success: true, Data: payload}.
// Если выключен — вызывает пользовательскую функцию textRender для человекочитаемой печати.
func (c *CLI) PrintResult(out io.Writer, payload interface{}, textRender func()) {
	if c.JSONOutput {
		_ = json.NewEncoder(out).Encode(CLIResponse{
			Success: true,
			Data:    payload,
		})
		return
	}
	// Если флага --json нет, запускаем красивый псевдографический вывод для человека
	textRender()
}

// PrintError централизованно обрабатывает любые сбои рантайма.
// Если включен JSON, он выплевывает в stdout структуру CLIResponse{Success: false, Error: ...} и возвращает nil, гася панику Cobra.
// Если выключен — возвращает оригинальную ошибку для стандартного вывода Cobra в stderr.
func (c *CLI) PrintError(out io.Writer, err error, contextMessage string) error {
	if err == nil {
		return nil
	}

	fullErr := fmt.Errorf("%s: %w", contextMessage, err)

	if c.JSONOutput {
		_ = json.NewEncoder(out).Encode(CLIResponse{
			Success: false,
			Error:   fullErr.Error(),
		})
		return nil // Возвращаем nil, чтобы Cobra не дублировала текст ошибки в stderr
	}

	return fullErr
}
