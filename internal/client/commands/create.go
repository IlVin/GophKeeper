package commands

import (
	"fmt"

	clientapp "gophkeeper/internal/client/app"

	"github.com/spf13/cobra"
)

type CreateConfig struct {
	Type  string
	Key   string
	Value string
}

func LoadCreateConfig(cmd *cobra.Command) (CreateConfig, error) {
	itemType, err := cmd.Flags().GetString("type")
	if err != nil {
		return CreateConfig{}, fmt.Errorf("get flag type: %w", err)
	}

	key, err := cmd.Flags().GetString("key")
	if err != nil {
		return CreateConfig{}, fmt.Errorf("get flag key: %w", err)
	}

	value, err := cmd.Flags().GetString("value")
	if err != nil {
		return CreateConfig{}, fmt.Errorf("get flag value: %w", err)
	}

	cfg := CreateConfig{
		Type:  trim(itemType),
		Key:   trim(key),
		Value: value,
	}

	return cfg, nil
}

func newCreateCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new secret",
		RunE: cli.withApp(func(cmd *cobra.Command, args []string, app *clientapp.App) error {
			cfg, err := LoadCreateConfig(cmd)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()

			fmt.Fprintln(out, "config file:", app.Config.App.ConfigFile)
			fmt.Fprintln(out, "ssh auth socket:", app.Config.SSH.AuthSock)
			fmt.Fprintln(out, "sqlite path:", app.Config.Storage.SQLitePath)
			fmt.Fprintln(out, "db open:", app.DB != nil)
			fmt.Fprintln(out, "type:", cfg.Type)
			fmt.Fprintln(out, "key:", cfg.Key)
			fmt.Fprintln(out, "value:", cfg.Value)

			return nil
		}),
	}

	cmd.Flags().String("type", "", "secret type")
	cmd.Flags().String("key", "", "secret key")
	cmd.Flags().String("value", "", "secret value")

	return cmd
}
