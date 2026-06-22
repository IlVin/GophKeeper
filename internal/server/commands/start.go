package commands

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

func (c *ServerCLI) newStartCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the secure GophKeeper storage server daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			// Вызываем инициализацию контейнера СТРОГО в момент старта целевой команды
			application, err := c.App(cmd.Context())
			if err != nil {
				return err
			}

			fmt.Fprintln(out, "✔ Server infrastructure successfully bootstrapped.")
			fmt.Fprintln(out, "gRPC Secure Server Listener active on", application.Config.Server.BindGRPC)

			if application.Config.Server.UseProxyProtocol {
				fmt.Fprintln(out, "PROXY protocol preamble parsing enabled.")
			}

			if application.Config.Server.LetsEncryptDomain != "" {
				fmt.Fprintln(out, "ACME Automated TLS enabled for domain:", application.Config.Server.LetsEncryptDomain)
				fmt.Fprintln(out, "ACME HTTP challenge port active on", application.Config.Server.BindHTTP)
			} else {
				fmt.Fprintln(out, "Running in local isolated mode via filesystem-loaded PKI trust roots")
			}

			// Настраиваем перехват сигналов завершения операционной системы для Graceful Shutdown
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

			// Запускаем сервер gRPC в отдельной горутине, чтобы не блокировать основной поток сигналов
			serverErrChan := make(chan error, 1)
			go func() {
				serverErrChan <- application.Run()
			}()

			// Ожидаем либо критической ошибки рантайма gRPC, либо сигнала остановки от ОС
			select {
			case err := <-serverErrChan:
				return fmt.Errorf("server runtime execution crashed: %w", err)
			case sig := <-sigChan:
				fmt.Fprintf(out, "\nReceived OS signal %v. Initiating graceful shutdown sequence...\n", sig)
				// Метод Close() внутри выполняет GracefulStop для gRPC и закрывает пулы pgxpool
				_ = c.Close()
				fmt.Fprintln(out, "✔ GophKeeper server stopped clean. Resources released.")
			}

			return nil
		},
	}

	return cmd
}
