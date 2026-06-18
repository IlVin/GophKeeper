package commands

import (
	"fmt"

	"gophkeeper/internal/client/providers/grpc"

	"github.com/spf13/cobra"
)

func newStatusCommand() *cobra.Command {
	var serverAddr string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check remote storage server status over TLS",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "Connecting to server at", serverAddr, "over TLS...")

			// Вызываем наш транспортный адаптер
			resp, err := grpc.FetchServerInfo(cmd.Context(), serverAddr)
			if err != nil {
				return err
			}

			// Печатаем то, что получили от сервера
			fmt.Fprintln(out, "\n--- Server Info Received ---")
			fmt.Fprintln(out, "Server Version: ", resp.GetServerVersion())
			fmt.Fprintln(out, "Environment:    ", resp.GetEnvironment())
			fmt.Fprintln(out, "DB Connected:   ", resp.GetDatabaseConnected())

			return nil
		},
	}

	// Флаг для указания адреса сервера, по умолчанию бьем в локальный сервер
	cmd.Flags().StringVar(&serverAddr, "server", "127.0.0.1:8081", "server grpcs address")
	return cmd
}
