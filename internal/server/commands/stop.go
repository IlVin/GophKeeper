package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newStopCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the GophKeeper storage server gracefully (Local shortcut placeholder)",
		RunE: func(cmd *cobra.Command, args []string) error {
			application, err := AppFromCommand(cmd)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "triggering context-bound graceful shutdown...")

			return application.Shutdown()
		},
	}

	return cmd
}
