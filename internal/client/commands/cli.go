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
	slog.Debug("Старт сборки корневого дерева CLI команд")
	cmd := &cobra.Command{
		Use:           "gophkeeper",
		Short:         "GophKeeper CLI — консольный криптографический менеджер секретов",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	if err := c.bindPersistentFlags(cmd); err != nil {
		slog.Error("Не удалось привязать глобальные флаги утилиты", "error", err)
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
			c.configErr = fmt.Errorf("чтение файла конфигурации: %w", err)
			return
		}

		cfg, err := clientconfig.LoadFromViper(c.v)
		if err != nil {
			c.configErr = fmt.Errorf("парсинг параметров из viper: %w", err)
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
		c.appErr = fmt.Errorf("сборка рантайм-контейнера: %w", err)
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

	slog.Debug("Инициировано закрытие ресурсов CLI слоя")
	err := clientapp.Shutdown(c.app)
	c.app = nil
	c.appErr = nil

	if err != nil {
		slog.Error("Сбой деструктора рантайма при закрытии CLI", "error", err)
		return fmt.Errorf("завершение работы рантайма: %w", err)
	}

	return nil
}

// bindPersistentFlags регистрирует сквозные флаги и маппит их в Viper.
func (c *CLI) bindPersistentFlags(cmd *cobra.Command) error {
	cmd.PersistentFlags().String("config", "", "Путь к YAML файлу конфигурации")
	cmd.PersistentFlags().String("sqlite-path", "", "Путь к локальной крипто-базе данных SQLite")
	cmd.PersistentFlags().BoolVar(&c.JSONOutput, "json", false, "Вывод результатов в виде чистого JSON-объекта для автоматизации")

	if err := c.v.BindPFlag("app.config_file", cmd.PersistentFlags().Lookup("config")); err != nil {
		return fmt.Errorf("привязка флага config: %w", err)
	}

	if err := c.v.BindPFlag("storage.sqlite_path", cmd.PersistentFlags().Lookup("sqlite-path")); err != nil {
		return fmt.Errorf("привязка флага sqlite-path: %w", err)
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
	)
}

// withOwnerCheck проверяет, что контейнер инициализирован и ключ разблокировки активен в ssh-agent.
// Реализует криптографический инвариант Proof of Possession (Проверка владельца).
func (c *CLI) withOwnerCheck(
	run func(cmd *cobra.Command, args []string) error,
) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		slog.Debug("Запуск криптографического барьера проверки прав владельца (withOwnerCheck)")

		// 1. Проверяем доступность SSH-агента в ОС
		if err := sshcheck.RequireAgent(); err != nil {
			slog.Error("Проверка владельца отклонена: ssh-agent недоступен")
			return fmt.Errorf("%w\n\n%s", err, sshcheck.FormatSSHAgentHelp())
		}

		// 2. Читаем локальное состояние синглтона из базы данных
		state, err := c.deviceStoreReader(cmd.Context())
		if err != nil {
			slog.Warn("Проверка прав прервана: локальное окружение не инициализировано")
			return err
		}

		// 3. Восстанавливаем публичный ключ инициализации
		dbPubKey, err := ssh.ParsePublicKey(state.SshPublicKey)
		if err != nil {
			slog.Error("Критическое повреждение структуры метаданных в SQLite", "error", err)
			return fmt.Errorf("структура БД повреждена (сбой парсинга публичного ключа): %w", err)
		}
		expectedFingerprint := sshagent.FingerprintSHA256(dbPubKey)
		slog.Debug("Извлечен целевой фингерпринт корня доверия", "fingerprint", expectedFingerprint)

		// 4. Подключаемся к агенту и верифицируем наличие закрытой части ключа
		agentClient, err := sshagent.NewFromEnv()
		if err != nil {
			return fmt.Errorf("подключение к сокету ssh-agent: %w", err)
		}
		defer agentClient.Close()

		_, err = agentClient.FindED25519ByFingerprint(expectedFingerprint)
		if err != nil {
			slog.Error("Доступ заблокирован: криптографический корень доверия отсутствует в агенте")
			return fmt.Errorf(
				"отказ в доступе: корневой криптографический ключ, использованный при 'init', отсутствует в вашем ssh-agent.\n"+
					"Ожидаемый фингерпринт: %s\n"+
					"Пожалуйста, добавьте ключ в агент через команду 'ssh-add'",
				expectedFingerprint,
			)
		}

		slog.Debug("Барьер Proof of Possession успешно пройден, делегирование управления команде")
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
		return nil, errors.New("клиентское окружение не инициализировано: пожалуйста, выполните команду 'gophkeeper init'")
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			slog.Error("Не удалось закрыть дескриптор БД в deviceStoreReader", "error", closeErr)
		}
	}()

	deviceStore := sqlite.NewSQLiteDeviceStore(db)
	return deviceStore.ReadDeviceState(ctx)
}

// PrintResult выполняет централизованный вывод успешных результатов сессии.
func (c *CLI) PrintResult(out io.Writer, payload interface{}, textRender func()) {
	if c.JSONOutput {
		slog.Debug("Форматирование успешного результата в JSON маркер")
		if err := json.NewEncoder(out).Encode(CLIResponse{Success: true, Data: payload}); err != nil {
			slog.Error("Сбой маршалинга JSON ответа", "error", err)
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
	slog.Error("Регистрация системного сбоя рантайма команды", "context", contextMessage, "error", err)

	if c.JSONOutput {
		if jsonErr := json.NewEncoder(out).Encode(CLIResponse{Success: false, Error: fullErr.Error()}); jsonErr != nil {
			slog.Error("Критический сбой маршалинга ошибки в JSON", "error", jsonErr)
		}
		return nil // Гасим панику Cobra, так как ответ уже записан в stdout конверт
	}

	return fullErr
}
