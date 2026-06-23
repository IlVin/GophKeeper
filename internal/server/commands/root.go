// Package commands координирует разворачивание дерева CLI-команд Cobra
// и оркестрирует инициализацию серверного рантайма GophKeeper.
package commands

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
)

// NewServerRootCommand конструирует корневую команду сервера Cobra
// и настраивает сквозную привязку флагов командной строки к конфигурации Viper.
//
// Функция жестко контролирует валидность маппинга полей (Fail-Fast), предотвращая
// запуск демона со скрытыми дефектами инициализации флагов.
func (c *ServerCLI) NewServerRootCommand() (*cobra.Command, error) {
	slog.Debug("Assembling server root Cobra command structure and mapping flags")

	cmd := &cobra.Command{
		Use:           "gophkeeper-server",
		Short:         "GophKeeper Stateful Blind Storage Server v4.1",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Регистрируем глобальные персистентные флаги рантайма среды сервера
	pFlags := cmd.PersistentFlags()
	pFlags.String("config", "", "path to server config file")
	pFlags.String("bind-http", ":80", "server HTTP bind address for Let's Encrypt challenges")
	pFlags.String("bind-grpc", ":443", "server gRPC secure listener bind address")
	pFlags.String("database", "", "postgres connection DSN")
	pFlags.String("lets-encrypt", "", "domain name for automatic Let's Encrypt TLS")
	pFlags.Bool("proxy-protocol", false, "enable go-proxyproto listener layer for upstream load-balancers")

	pFlags.String("server-ca-key", "", "path to Server CA private key file")
	pFlags.String("device-ca-key", "", "path to Device Identity CA private key file")

	// Явный перехват и валидация ошибок биндинга для предотвращения немых сбоев
	if err := c.v.BindPFlag("server.config_file", pFlags.Lookup("config")); err != nil {
		return nil, fmt.Errorf("failed to bind flag 'config': %w", err)
	}
	if err := c.v.BindPFlag("server.bind_http", pFlags.Lookup("bind-http")); err != nil {
		return nil, fmt.Errorf("failed to bind flag 'bind-http': %w", err)
	}
	if err := c.v.BindPFlag("server.bind_grpc", pFlags.Lookup("bind-grpc")); err != nil {
		return nil, fmt.Errorf("failed to bind flag 'bind-grpc': %w", err)
	}
	if err := c.v.BindPFlag("storage.postgres_dsn", pFlags.Lookup("database")); err != nil {
		return nil, fmt.Errorf("failed to bind flag 'database': %w", err)
	}
	if err := c.v.BindPFlag("server.lets_encrypt_domain", pFlags.Lookup("lets-encrypt")); err != nil {
		return nil, fmt.Errorf("failed to bind flag 'lets-encrypt': %w", err)
	}
	if err := c.v.BindPFlag("server.use_proxy_protocol", pFlags.Lookup("proxy-protocol")); err != nil {
		return nil, fmt.Errorf("failed to bind flag 'proxy-protocol': %w", err)
	}
	if err := c.v.BindPFlag("pki.server_ca_key_path", pFlags.Lookup("server-ca-key")); err != nil {
		return nil, fmt.Errorf("failed to bind flag 'server-ca-key': %w", err)
	}
	if err := c.v.BindPFlag("pki.device_ca_key_path", pFlags.Lookup("device-ca-key")); err != nil {
		return nil, fmt.Errorf("failed to bind flag 'device-ca-key': %w", err)
	}

	// Регистрируем подкоманды, передавая ссылку на ленивый контекст ServerCLI
	cmd.AddCommand(c.newStartCommand())
	cmd.AddCommand(c.newVersionCommand())

	slog.Debug("Server root Cobra command compiled successfully with secure parameters mapping")
	return cmd, nil
}
