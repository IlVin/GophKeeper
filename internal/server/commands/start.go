// Package commands координирует разворачивание дерева CLI-команд Cobra
// и оркестрирует инициализацию серверного рантайма GophKeeper.
package commands

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// newStartCommand конструирует дочернюю команду 'start' для Cobra.
//
// Команда запускает асинхронное сетевое вещание gRPC-сервера в фоновой горутине
// и блокирует основной поток, ожидая системных сигналов SIGINT/SIGTERM для
// безопасной финализации пулов СУБД (Graceful Shutdown) (Инварианты №4, №15).
func (c *ServerCLI) newStartCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the secure GophKeeper storage server daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			// Ленивая инициализация и бутстрап контейнера СТРОГО в момент старта команды
			application, err := c.App(cmd.Context())
			if err != nil {
				slog.Error("Failed to bootstrap server core infrastructure inside start command execution", "error", err)
				return err
			}

			slog.Info("Server infrastructure successfully bootstrapped",
				"bind_grpc", application.Config.Server.BindGRPC,
				"proxy_protocol", application.Config.Server.UseProxyProtocol,
			)

			if application.Config.Server.LetsEncryptDomain != "" {
				slog.Info("ACME Automated TLS initialized for domain identity",
					"domain", application.Config.Server.LetsEncryptDomain,
					"bind_http", application.Config.Server.BindHTTP,
				)
			} else {
				slog.Info("Running in local isolated server mode via filesystem PKI trust roots")
			}

			// Настраиваем перехват сигналов завершения операционной системы для Graceful Shutdown
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
			defer signal.Stop(sigChan)

			// Запускаем сервер gRPC в отдельной горутине, чтобы не блокировать поток сигналов ОС
			serverErrChan := make(chan error, 1)
			go func() {
				serverErrChan <- application.Run()
			}()

			fmt.Fprintln(out, "✔ GophKeeper secure daemon initialized. Listen channel open.")

			// Ожидаем либо критической ошибки рантайма gRPC, либо сигнала остановки от ОС
			select {
			case err := <-serverErrChan:
				slog.Error("Server network listener runtime execution collapsed unexpectedly", "error", err)
				return fmt.Errorf("server runtime execution crashed: %w", err)
			case sig := <-sigChan:
				slog.Info("Received termination OS signal, initiating graceful shutdown sequence", "signal", sig.String())
				fmt.Fprintf(out, "\nReceived OS signal %v. Finalizing active pools...\n", sig)

				// ИСПРАВЛЕНО: Явный контроль и проброс ошибок закрытия ресурсов для исключения утечек в ОС
				if closeErr := c.Close(); closeErr != nil {
					slog.Error("Resource cleanup transaction crashed during command finalization phase", "error", closeErr)
					return fmt.Errorf("failed to shutdown server cleanly: %w", closeErr)
				}

				slog.Info("GophKeeper cloud daemon stopped clean. Active descriptors released.")
				fmt.Fprintln(out, "✔ GophKeeper server stopped clean.")
			}

			return nil
		},
	}

	return cmd
}
