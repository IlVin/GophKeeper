package commands

import (
	"fmt"

	"gophkeeper/internal/client/providers/grpc"

	"github.com/spf13/cobra"
)

type StatusConfig struct {
	ServerAddr string
}

func LoadStatusConfig(cmd *cobra.Command) (StatusConfig, error) {
	serverAddr, err := cmd.Flags().GetString("server")
	if err != nil {
		return StatusConfig{}, fmt.Errorf("get flag server: %w", err)
	}

	cfg := StatusConfig{
		ServerAddr: trim(serverAddr),
	}

	if cfg.ServerAddr == "" {
		return StatusConfig{}, fmt.Errorf("server address is required")
	}

	return cfg, nil
}

func newStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check remote storage server status over TLS",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadStatusConfig(cmd)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "Connecting to server at", cfg.ServerAddr, "over TLS...")

			resp, err := grpc.FetchServerInfo(cmd.Context(), cfg.ServerAddr)
			if err != nil {
				return fmt.Errorf("fetch server info: %w", err)
			}

			fmt.Fprintln(out)
			fmt.Fprintln(out, "--- Server Info Received ---")
			fmt.Fprintln(out, "Server Version: ", resp.GetServerVersion())
			fmt.Fprintln(out, "Environment:    ", resp.GetEnvironment())
			fmt.Fprintln(out, "DB Connected:   ", resp.GetDatabaseConnected())

			return nil
		},
	}

	cmd.Flags().String("server", "127.0.0.1:8081", "server GRPCS address")

	return cmd
}
