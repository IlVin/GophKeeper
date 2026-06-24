// Package commands инкапсулирует CLI-слой, дерево команд Cobra и инфраструктурные
// middleware для контроля доступа и управления ресурсами утилиты GophKeeper.
package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

const maxCallMsgSize = 32 * 1024 * 1024 // 32 Мегабайта

// CLIResponse описывает унифицированный JSON-конверт для автоматизации и E2E-тестирования.
type CLIResponse struct {
	Success bool        `json:"success"`
	Error   string      `json:"error,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// CLI управляет контекстом выполнения консольных команд, ленивой инициализацией
// рантайм-компонентов и централизованным форматированием вывода.
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

// NewCLI конструирует экземпляр координатора CLI-слоя.
func NewCLI(v *viper.Viper) *CLI {
	return &CLI{v: v}
}

// NewRootCommand собирает корневое дерево команд Cobra, настраивает флаги
// и подавляет встроенные механизмы вывода ошибок для обеспечения кастомного UX.
func (c *CLI) NewRootCommand() (*cobra.Command, error) {
	slog.Debug("Building root CLI command tree")
	cmd := &cobra.Command{
		Use:           "gophkeeper",
		Short:         "GophKeeper CLI — консольный криптографический менеджер секретов",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	if err := c.bindPersistentFlags(cmd); err != nil {
		slog.Error("Failed to bind global flags", "error", err)
		return nil, err
	}

	c.addCommands(cmd)
	return cmd, nil
}

// Viper возвращает текущий экземпляр конфигурационного движка сессии.
func (c *CLI) Viper() *viper.Viper {
	return c.v
}

// AppConfig лениво загружает, парсит и валидирует иммутабельную модель конфигурации.
func (c *CLI) AppConfig() (clientconfig.Config, error) {
	c.configOnce.Do(func() {
		if err := clientconfig.ReadConfigFile(c.v); err != nil {
			c.configErr = fmt.Errorf("read config file: %w", err)
			return
		}

		cfg, err := clientconfig.LoadFromViper(c.v)
		if err != nil {
			c.configErr = fmt.Errorf("parse params from viper: %w", err)
			return
		}

		c.config = cfg
	})

	if c.configErr != nil {
		return clientconfig.Config{}, c.configErr
	}

	return c.config, nil
}

// DBPath возвращает проверенный путь к локальному контейнеру базы данных.
func (c *CLI) DBPath() (string, error) {
	cfg, err := c.AppConfig()
	if err != nil {
		return "", err
	}
	return cfg.Storage().SQLitePath(), nil
}

// App лениво инициализирует и возвращает потокобезопасный рантайм-контейнер приложения.
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
		c.appErr = fmt.Errorf("build runtime container: %w", err)
		return nil, c.appErr
	}

	c.app = app
	c.appErr = nil
	return c.app, nil
}

// Close осуществляет контролируемое закрытие всех дескрипторов СУБД и зачистку RAM.
func (c *CLI) Close() error {
	c.appMu.Lock()
	defer c.appMu.Unlock()

	if c.app == nil {
		return nil
	}

	slog.Debug("Initiating CLI layer resource cleanup")
	err := clientapp.Shutdown(c.app)
	c.app = nil
	c.appErr = nil

	if err != nil {
		slog.Error("Runtime destructor failed during CLI shutdown", "error", err)
		return fmt.Errorf("runtime shutdown: %w", err)
	}

	return nil
}

// bindPersistentFlags регистрирует сквозные флаги и маппит их в Viper.
func (c *CLI) bindPersistentFlags(cmd *cobra.Command) error {
	cmd.PersistentFlags().String("config", "", "Path to YAML config file")
	cmd.PersistentFlags().String("sqlite-path", "", "Path to local crypto SQLite database")
	cmd.PersistentFlags().BoolVar(&c.JSONOutput, "json", false, "Output as clean JSON object for automation")

	if err := c.v.BindPFlag("app.config_file", cmd.PersistentFlags().Lookup("config")); err != nil {
		return fmt.Errorf("bind config flag: %w", err)
	}

	if err := c.v.BindPFlag("storage.sqlite_path", cmd.PersistentFlags().Lookup("sqlite-path")); err != nil {
		return fmt.Errorf("bind sqlite-path flag: %w", err)
	}

	return nil
}

// addCommands подключает дочерние команды к корневому дереву CLI.
func (c *CLI) addCommands(cmd *cobra.Command) {
	cmd.AddCommand(
		newInitCommand(c),
		newRegisterCommand(c),
		newCreateCommand(c),
		newListCommand(c),
		newGetCommand(c),
		newDeleteCommand(c),
		newSyncCommand(c),
		newVersionCommand(c),
	)
}

// withOwnerCheck проверяет, что контейнер инициализирован и ключ разблокировки активен в ssh-agent.
// Реализует криптографический инвариант Proof of Possession (Проверка владельца).
func (c *CLI) withOwnerCheck(
	run func(cmd *cobra.Command, args []string) error,
) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		slog.Debug("Starting cryptographic owner check barrier (withOwnerCheck)")

		// 1. Проверяем доступность SSH-агента в ОС
		if err := sshcheck.RequireAgent(); err != nil {
			slog.Error("Owner check rejected: ssh-agent unavailable")
			return fmt.Errorf("%w\n\n%s", err, sshcheck.FormatSSHAgentHelp())
		}

		// 2. Читаем локальное состояние синглтона из базы данных
		state, err := c.deviceStoreReader(cmd.Context())
		if err != nil {
			slog.Warn("Owner check aborted: local environment not initialized")
			return err
		}

		// 3. Восстанавливаем публичный ключ инициализации
		dbPubKey, err := ssh.ParsePublicKey(state.SshPublicKey)
		if err != nil {
			slog.Error("Critical metadata structure corruption in SQLite", "error", err)
			return fmt.Errorf("DB structure corrupted (public key parse failed): %w", err)
		}
		expectedFingerprint := sshagent.FingerprintSHA256(dbPubKey)
		slog.Debug("Extracted target root of trust fingerprint", "fingerprint", expectedFingerprint)

		// 4. Подключаемся к агенту и верифицируем наличие закрытой части ключа
		agentClient, err := sshagent.NewFromEnv()
		if err != nil {
			return fmt.Errorf("connect to ssh-agent socket: %w", err)
		}
		defer agentClient.Close()

		_, err = agentClient.FindED25519ByFingerprint(expectedFingerprint)
		if err != nil {
			slog.Error("Access denied: cryptographic root of trust missing from agent")
			return fmt.Errorf(
				"Access denied: root cryptographic key used for .init. is missing from your ssh-agent.\n"+
					"Expected fingerprint: %s\n"+
					"Please add the key to agent using .ssh-add.",
				expectedFingerprint,
			)
		}

		slog.Debug("Proof of Possession barrier passed, delegating to command")
		return run(cmd, args)
	}
}

// deviceStoreReader вычитывает состояние устройства до полной сборки общего контекста cli.App()
func (c *CLI) deviceStoreReader(ctx context.Context) (*repository.LocalDeviceState, error) {
	cfg, err := c.AppConfig()
	if err != nil {
		return nil, err
	}

	sqlitePath := cfg.Storage().SQLitePath()

	// Открываем легковесное изолированное соединение строго под чтение статуса
	db, err := sqlite.Open(sqlitePath)
	if err != nil {
		return nil, errors.New("client environment not initialized: please run .gophkeeper init.")
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			slog.Error("Failed to close DB descriptor in deviceStoreReader", "error", closeErr)
		}
	}()

	deviceStore := sqlite.NewSQLiteDeviceStore(db)
	return deviceStore.ReadDeviceState(ctx)
}

// PrintResult выполняет централизованный вывод успешных результатов сессии.
func (c *CLI) PrintResult(out io.Writer, payload interface{}, textRender func()) {
	if c.JSONOutput {
		slog.Debug("Formatting success result as JSON marker")
		if err := json.NewEncoder(out).Encode(CLIResponse{Success: true, Data: payload}); err != nil {
			slog.Error("JSON response marshaling failed", "error", err)
			fmt.Fprintf(out, `{"success":false,"error":"internal json formatting error: %v"}`+"\n", err)
		}
		return
	}
	textRender()
}

// PrintError выполняет централизованную обработку, логирование и форматирование сбоев.
func (c *CLI) PrintError(out io.Writer, err error, contextMessage string) error {
	if err == nil {
		return nil
	}

	fullErr := fmt.Errorf("%s: %w", contextMessage, err)
	slog.Error("Registering system command runtime failure", "context", contextMessage, "error", err)

	if c.JSONOutput {
		if jsonErr := json.NewEncoder(out).Encode(CLIResponse{Success: false, Error: fullErr.Error()}); jsonErr != nil {
			slog.Error("Critical JSON error marshaling failure", "error", jsonErr)
		}
		return nil // Гасим панику Cobra, так как ответ уже записан в stdout конверт
	}

	return fullErr
}
