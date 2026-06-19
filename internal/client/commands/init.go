package commands

import (
	"fmt"

	clientconfig "gophkeeper/internal/client/config"
	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/sshcheck"

	"github.com/spf13/cobra"
)

func newInitCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize local GophKeeper environment",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := sshcheck.RequireAgent(); err != nil {
				return fmt.Errorf("%w\n\n%s", err, sshcheck.FormatSSHAgentHelp())
			}

			cfg, err := cli.AppConfig()
			if err != nil {
				return fmt.Errorf("load app config: %w", err)
			}

			if err := clientconfig.WriteDefaultConfigFile(cfg.App.ConfigFile, cfg); err != nil {
				return fmt.Errorf("write config file: %w", err)
			}

			db, err := sqlite.Bootstrap(cfg.Storage.SQLitePath)
			if err != nil {
				return fmt.Errorf("bootstrap sqlite storage: %w", err)
			}
			defer func() {
				_ = db.Close()
			}()

			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "GophKeeper initialized.")
			fmt.Fprintln(out, "Config file:", cfg.App.ConfigFile)
			fmt.Fprintln(out, "SQLite path:", cfg.Storage.SQLitePath)

			return nil
		},
	}

	return cmd
}
