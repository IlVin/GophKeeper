package commands

import (
	"github.com/spf13/cobra"
)

func (c *ServerCLI) NewServerRootCommand() (*cobra.Command, error) {
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

	// Намертво привязываем флаги CLI к маппингу конфигурации Viper
	_ = c.v.BindPFlag("server.config_file", pFlags.Lookup("config"))
	_ = c.v.BindPFlag("server.bind_http", pFlags.Lookup("bind-http"))
	_ = c.v.BindPFlag("server.bind_grpc", pFlags.Lookup("bind-grpc"))
	_ = c.v.BindPFlag("storage.postgres_dsn", pFlags.Lookup("database"))
	_ = c.v.BindPFlag("server.lets_encrypt_domain", pFlags.Lookup("lets-encrypt"))
	_ = c.v.BindPFlag("server.use_proxy_protocol", pFlags.Lookup("proxy-protocol"))

	_ = c.v.BindPFlag("pki.server_ca_key_path", pFlags.Lookup("server-ca-key"))
	_ = c.v.BindPFlag("pki.device_ca_key_path", pFlags.Lookup("device-ca-key"))

	// Регистрируем подкоманды, передавая ссылку на ленивый контекст ServerCLI
	cmd.AddCommand(c.newStartCommand())

	return cmd, nil
}
