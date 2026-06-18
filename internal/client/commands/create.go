package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newCreateCommand() *cobra.Command {
	var itemType string
	var key string
	var value string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			application, err := AppFromCommand(cmd)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()

			fmt.Fprintln(out, "config file:", application.Config.App.ConfigFile)
			fmt.Fprintln(out, "ssh auth socket:", application.Config.SSHAgent.SocketPath)
			fmt.Fprintln(out, "sqlite path:", application.Config.Storage.SQLitePath)
			fmt.Fprintln(out, "db open:", application.DB != nil)
			fmt.Fprintln(out, "type:", itemType)
			fmt.Fprintln(out, "key:", key)
			fmt.Fprintln(out, "value:", value)

			return nil
		},
	}

	cmd.Flags().StringVar(&itemType, "type", "", "secret type")
	cmd.Flags().StringVar(&key, "key", "", "secret key")
	cmd.Flags().StringVar(&value, "value", "", "secret value")

	return cmd
}
