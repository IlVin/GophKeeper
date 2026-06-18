package commands

import (
	"fmt"

	clientapp "gophkeeper/internal/client/app"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func NewRootCommand(v *viper.Viper) (*cobra.Command, error) {
	var configFile string

	cmd := &cobra.Command{
		Use:   "gophkeeper",
		Short: "GophKeeper CLI",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			ctx, _, err := clientapp.Bootstrap(cmd.Context(), v)
			if err != nil {
				return err
			}

			cmd.SetContext(ctx)
			cmd.Root().SetContext(ctx)

			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			application, err := AppFromCommand(cmd)
			if err != nil {
				return nil
			}

			return clientapp.Shutdown(application)
		},
	}

	cmd.PersistentFlags().StringVar(&configFile, "config", "", "path to config file")
	cmd.PersistentFlags().String("ssh-auth-sock", "", "path to SSH auth socket")
	cmd.PersistentFlags().String("sqlite-path", "", "path to local SQLite database")

	if err := v.BindPFlag("app.config_file", cmd.PersistentFlags().Lookup("config")); err != nil {
		return nil, fmt.Errorf("bind flag config: %w", err)
	}

	if err := v.BindPFlag("ssh_agent.socket_path", cmd.PersistentFlags().Lookup("ssh-auth-sock")); err != nil {
		return nil, fmt.Errorf("bind flag ssh-auth-sock: %w", err)
	}

	if err := v.BindPFlag("storage.sqlite_path", cmd.PersistentFlags().Lookup("sqlite-path")); err != nil {
		return nil, fmt.Errorf("bind flag sqlite-path: %w", err)
	}

	cmd.AddCommand(newCreateCommand())
	cmd.AddCommand(newStatusCommand())

	return cmd, nil
}
