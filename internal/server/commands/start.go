package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newStartCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the GophKeeper storage server",
		RunE: func(cmd *cobra.Command, args []string) error {
			application, err := AppFromCommand(cmd)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "starting gRPC secure server on", application.Config.Server.BindGRPC)
			if application.Config.Server.LetsEncryptDomain != "" {
				fmt.Fprintln(out, "ACME domain enabled:", application.Config.Server.LetsEncryptDomain)
				fmt.Fprintln(out, "ACME HTTP challenge listener active on", application.Config.Server.BindHTTP)
			} else {
				// ИСПРАВЛЕНО: Текст логов приведен в соответствие со спецификацией внешней загрузки PKI v4.0
				fmt.Fprintln(out, "running in local isolated mTLS mode via filesystem-loaded CA keys")
				fmt.Fprintln(out, "Server CA private key used:", application.Config.PKI.ServerCAKeyPath)
				fmt.Fprintln(out, "Device CA private key used:", application.Config.PKI.DeviceCAKeyPath)
			}
			fmt.Fprintln(out, "connected database storage:", application.Config.Storage.PostgresDSN)

			return application.Run()
		},
	}

	return cmd
}
