package commands

import (
	serverapp "gophkeeper/internal/server/app"

	"github.com/spf13/cobra"
)

func AppFromCommand(cmd *cobra.Command) (*serverapp.App, error) {
	return serverapp.AppFromContext(cmd.Context())
}
