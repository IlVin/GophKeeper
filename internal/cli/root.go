package cli

import (
	"fmt"

	"gophkeeper/internal/config"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func NewRootCommand(v *viper.Viper) (*cobra.Command, error) {
	var configFile string

	cmd := &cobra.Command{
		Use:   "gophkeeper",
		Short: "GophKeeper CLI",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if configFile != "" {
				v.SetConfigFile(configFile)

				if err := v.ReadInConfig(); err != nil {
					return fmt.Errorf("read config file: %w", err)
				}
			}

			cfg, err := config.LoadFromViper(v)
			if err != nil {
				return err
			}

			ctx := withConfig(cmd.Context(), cfg)
			cmd.SetContext(ctx)
			cmd.Root().SetContext(ctx)

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&configFile, "config", "", "path to config file")
	cmd.PersistentFlags().String("ssh-auth-sock", "", "path to SSH auth socket")

	if err := v.BindPFlag("app.config_file", cmd.PersistentFlags().Lookup("config")); err != nil {
		return nil, fmt.Errorf("bind flag config: %w", err)
	}

	if err := v.BindPFlag("ssh_agent.socket_path", cmd.PersistentFlags().Lookup("ssh-auth-sock")); err != nil {
		return nil, fmt.Errorf("bind flag ssh-auth-sock: %w", err)
	}

	cmd.AddCommand(newCreateCommand())

	return cmd, nil
}
