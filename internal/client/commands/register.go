// Package commands предоставляет реализации консольных команд Cobra для
// криптографического взаимодействия с хранилищем GophKeeper.
package commands

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/service"
	"gophkeeper/internal/client/sshcheck"
	"gophkeeper/internal/shared/certs"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
)

// newRegisterCommand конструирует CLI-команду "register" для привязки
// локального сейфа к облачному аккаунту через двухэтапный протокол Zero-Knowledge Challenge.
func newRegisterCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Attach local vault to cloud account via cryptographic SSH challenge",
		Long:  `Performs two-step cloud Ed25519 key ownership authorization via encrypted TLS 1.3 channel and imports mTLS passport.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			slog.Info("Starting network device registration command")

			// 1. ПРОВЕРКА МАТРИЦЫ PRECONDITIONS
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ssh-agent check error")
			}

			// Разбираем эфемерные параметры вызова
			flags := cmd.Flags()
			serverAddr, _ := flags.GetString("server")
			serverAddr = strings.TrimSpace(serverAddr)

			if serverAddr == "" {
				return cli.PrintError(out, errors.New("--server parameter is required and cannot be empty"), "flag validation")
			}

			// 2. ПРОВЕРКА СОСТОЯНИЯ КОНТЕЙНЕРА (Барьер конечного автомата жизненного цикла)
			app, err := cli.App(cmd.Context())
			if err != nil {
				return cli.PrintError(out, err, "application context startup")
			}

			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB())
			localState, err := deviceStore.ReadDeviceState(cmd.Context())
			if err != nil {
				return cli.PrintError(out, err, "reading local device status")
			}

			// Критерий успешной сетевой регистрации — наличие mTLS паспорта устройства
			if localState.ClientCertificate != nil && len(*localState.ClientCertificate) > 0 {
				serverURLStr := "unknown"
				if localState.ServerURL != nil {
					serverURLStr = *localState.ServerURL
				}
				statusErr := fmt.Errorf("container already registered and contains active mTLS passport (Server: %s, UserID: %s)", serverURLStr, *localState.UserID)
				slog.Warn("Attempted re-registration blocked by state machine", "user_id", *localState.UserID)
				return cli.PrintError(out, statusErr, "status validation")
			}

			// 3. РАБОТА С SSH КЛЮЧОМ И АГЕНТОМ
			dbPubKey, err := ssh.ParsePublicKey(localState.SshPublicKey)
			if err != nil {
				return cli.PrintError(out, err, "public key metadata structure corrupted")
			}
			expectedFingerprint := sshagent.FingerprintSHA256(dbPubKey)

			// Проверяем реальное наличие в ssh-agent ключа, с которым делали init
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "connect to ssh-agent socket")
			}

			agentClosedChecked := false
			defer func() {
				if !agentClosedChecked {
					if closeErr := agentClient.Close(); closeErr != nil {
						slog.Error("Failed to close UNIX agent socket in register defer", "error", closeErr)
					}
				}
			}()

			if _, err = agentClient.FindED25519ByFingerprint(expectedFingerprint); err != nil {
				agentErr := fmt.Errorf("root cryptographic initialization key (%s) must be loaded in your ssh-agent. Run .ssh-add.", expectedFingerprint)
				return cli.PrintError(out, agentErr, "access denied")
			}

			// 4. НАСТРОЙКА СЕТЕВОГО ТРАНСПОРТА (Строго изолированный TLS 1.3 с динамическим Hostname)
			targetHost, _, err := net.SplitHostPort(serverAddr)
			if err != nil {
				targetHost = serverAddr
			}

			serverCAPool, err := certs.LoadServerCAPool()
			if err != nil {
				return cli.PrintError(out, err, "loading embedded trusted certificate pool")
			}

			tlsCfg := &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: targetHost,
				RootCAs:    serverCAPool, // Намертво привязываем клиента к нашему Server CA
			}

			slog.Debug("Opening isolated secure gRPC TLS 1.3 channel", "sni", targetHost)
			conn, err := grpc.NewClient(
				serverAddr,
				grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
				grpc.WithDefaultCallOptions(
					grpc.MaxCallRecvMsgSize(maxCallMsgSize),
					grpc.MaxCallSendMsgSize(maxCallMsgSize),
				),
			)
			if err != nil {
				return cli.PrintError(out, err, "gRPC network client initialization")
			}

			connClosedChecked := false
			defer func() {
				if !connClosedChecked {
					if closeErr := conn.Close(); closeErr != nil {
						slog.Error("Failed to close gRPC connection in register defer", "error", closeErr)
					}
				}
			}()

			// Запускаем немедленный TLS-хендшейк
			conn.Connect()

			// Ждем установления физического SSL-соединения с защитой от бесконечного подвисания
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()

			for {
				state := conn.GetState()
				slog.Debug("gRPC transport auth state transition", "state", state.String())

				if state == connectivity.Ready {
					break
				}
				if state == connectivity.TransientFailure || state == connectivity.Shutdown {
					connErr := fmt.Errorf("secure gRPC TLS channel establishment aborted (system status: %s)", state)
					return cli.PrintError(out, connErr, "network failure")
				}
				if !conn.WaitForStateChange(ctx, state) {
					timeoutErr := errors.New("TLS 1.3 secure handshake timeout expired")
					return cli.PrintError(out, timeoutErr, "таймаут сети")
				}
			}

			slog.Info("Physical TLS 1.3 channel verified, starting Composition Root")

			// 5. ИНИЦИАЛИЗАЦИЯ СЕРВИСОВ И ЗАПУСК КРИПТОГРАФИЧЕСКОГО КОНВЕЙЕРА РЕГИСТРАЦИИ
			initService := service.NewInitService(deviceStore, agentClient)
			regService := service.NewRegisterService(deviceStore, initService, agentClient, conn)

			err = regService.RunRegistration(cmd.Context(), serverAddr)
			if err != nil {
				slog.Error("Cryptographic registration pipeline crashed", "error", err)
				return cli.PrintError(out, err, "registration pipeline failure")
			}

			// Безопасно финализируем ресурсы до вывода результатов на экран
			if closeErr := agentClient.Close(); closeErr != nil {
				slog.Error("Failed to close agent socket on successful exit from register", "error", closeErr)
			}
			agentClosedChecked = true

			if closeErr := conn.Close(); closeErr != nil {
				slog.Error("Failed to close gRPC transport on successful exit from register", "error", closeErr)
			}
			connClosedChecked = true

			// Формируем структурированный payload ответа
			payload := RegisterResponse{
				UserID:    expectedFingerprint,
				ServerURL: serverAddr,
				Status:    "REGISTERED",
			}

			cli.PrintResult(out, payload, func() {
				fmt.Fprintf(out, "Establishing TLS 1.3 channel to node %s [TLS SNI: %s]...\n", serverAddr, targetHost)
				fmt.Fprintln(out, "Starting two-step passwordless mutual verification protocol...")
				fmt.Fprintf(out, "\n✔ SUCCESS! Container successfully attached to cloud account %q.\n", expectedFingerprint)
				fmt.Fprintln(out, "mTLS device passport received and saved. Status changed to: REGISTERED")
			})

			return nil
		},
	}

	// Регистрация флага вызова
	cmd.Flags().String("server", "", "Address of trusted GophKeeper server in HOST:PORT format")
	_ = cmd.MarkFlagRequired("server")

	return cmd
}
