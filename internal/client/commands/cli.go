package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	clientapp "gophkeeper/internal/client/app"
	clientconfig "gophkeeper/internal/client/config"
	"gophkeeper/internal/client/sshcheck"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type CLI struct {
	v *viper.Viper

	configOnce sync.Once
	config     clientconfig.Config
	configErr  error

	appMu  sync.Mutex
	app    *clientapp.App
	appErr error
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
