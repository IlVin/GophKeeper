package commands

import (
	"fmt"

	serverapp "gophkeeper/internal/server/app"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func NewServerRootCommand(v *viper.Viper) (*cobra.Command, error) {
	var configFile string

	cmd := &cobra.Command{
		Use:   "gophkeeper-server",
		Short: "GophKeeper Server CLI",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			ctx, _, err := serverapp.Bootstrap(cmd.Context(), v)
			if err != nil {
				return err
			}

			cmd.SetContext(ctx)
			cmd.Root().SetContext(ctx)

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&configFile, "config", "", "path to server config file")
	cmd.PersistentFlags().String("bind-http", "", "server HTTP bind address for Let's Encrypt challenges")
	cmd.PersistentFlags().String("bind-grpc", "", "server gRPC secure listener bind address")
	cmd.PersistentFlags().String("database", "", "postgres connection dsn")
	cmd.PersistentFlags().String("lets-encrypt", "", "domain name for automatic Let's Encrypt TLS")

	cmd.PersistentFlags().String("server-ca-key", "", "path to Server CA private key file")
	cmd.PersistentFlags().String("device-ca-key", "", "path to Device Identity CA private key file")
	cmd.PersistentFlags().String("device-ca-crt", "", "path to Device Identity CA public certificate file")

	if err := v.BindPFlag("server.config_file", cmd.PersistentFlags().Lookup("config")); err != nil {
		return nil, fmt.Errorf("bind flag config: %w", err)
	}
	if err := v.BindPFlag("server.bind_http", cmd.PersistentFlags().Lookup("bind-http")); err != nil {
		return nil, fmt.Errorf("bind flag bind-http: %w", err)
	}
	if err := v.BindPFlag("server.bind_grpc", cmd.PersistentFlags().Lookup("bind-grpc")); err != nil {
		return nil, fmt.Errorf("bind flag bind-grpc: %w", err)
	}
	if err := v.BindPFlag("storage.postgres_dsn", cmd.PersistentFlags().Lookup("database")); err != nil {
		return nil, fmt.Errorf("bind flag database: %w", err)
	}
	if err := v.BindPFlag("server.lets_encrypt_domain", cmd.PersistentFlags().Lookup("lets-encrypt")); err != nil {
		return nil, fmt.Errorf("bind flag lets-encrypt: %w", err)
	}

	// ДОБАВЛЕНО: Связывание флагов PKI путей с конфигурационной мапой Viper
	if err := v.BindPFlag("pki.server_ca_key_path", cmd.PersistentFlags().Lookup("server-ca-key")); err != nil {
		return nil, fmt.Errorf("bind flag server-ca-key: %w", err)
	}
	if err := v.BindPFlag("pki.device_ca_key_path", cmd.PersistentFlags().Lookup("device-ca-key")); err != nil {
		return nil, fmt.Errorf("bind flag device-ca-key: %w", err)
	}
	if err := v.BindPFlag("pki.device_ca_cert_path", cmd.PersistentFlags().Lookup("device-ca-crt")); err != nil {
		return nil, fmt.Errorf("bind flag device-ca-crt: %w", err)
	}

	cmd.AddCommand(newStartCommand())
	cmd.AddCommand(newStopCommand())

	return cmd, nil
}
