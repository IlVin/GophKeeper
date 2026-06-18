package commands

import (
	clientapp "gophkeeper/internal/client/app"

	"github.com/spf13/cobra"
)

func AppFromCommand(cmd *cobra.Command) (*clientapp.App, error) {
	return clientapp.AppFromContext(cmd.Context())
}
