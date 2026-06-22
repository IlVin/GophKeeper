package commands

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
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

// newRegisterCommand конструирует команду инициации сетевой регистрации устройства.
func newRegisterCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Bind local container to a server account via secure passwordless SSH challenge",
		Long: `Performs a two-step zero-knowledge registration protocol over secure TLS 1.3.
Verifies cryptographic possession of the Ed25519 key active in ssh-agent, 
publishes the cloud bootstrap envelope, and obtains a container mTLS identity certificate.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			// 1. ПРОВЕРКА МАТРИЦЫ PRECONDITIONS (SSH Agent обязателен)
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ssh agent error")
			}

			// Разбираем эфемерные параметры вызова (УБРАН флаг --pub-key)
			flags := cmd.Flags()
			serverAddr, _ := flags.GetString("server")

			serverAddr = trim(serverAddr)

			// 2. ПРОВЕРКА СОСТОЯНИЯ КОНТЕЙНЕРА (Жесткий барьер конечного автомата жизненного цикла)
			app, err := cli.App(cmd.Context())
			if err != nil {
				return cli.PrintError(out, err, "client environment is not initialized: run 'gophkeeper init' first")
			}

			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB)
			localState, err := deviceStore.ReadDeviceState(cmd.Context())
			if err != nil {
				return cli.PrintError(out, err, "failed to read local device state")
			}

			// Настоящим критерием успешной сетевой регистрации является наличие mTLS паспорта устройства
			if localState.ClientCertificate != nil && len(*localState.ClientCertificate) > 0 {
				serverURLStr := "unknown"
				if localState.ServerURL != nil {
					serverURLStr = *localState.ServerURL
				}
				statusErr := fmt.Errorf("client container is already registered and issued an mTLS passport (Server URL: %s, UserID: %s)", serverURLStr, *localState.UserID)
				return cli.PrintError(out, statusErr, "validation failed")
			}

			// 3. РАБОТА С SSH КЛЮЧОМ И АГЕНТОМ (ИСПРАВЛЕНО: Достаем ключ напрямую из локальной БД)
			dbPubKey, err := ssh.ParsePublicKey(localState.SshPublicKey)
			if err != nil {
				return cli.PrintError(out, err, "failed to parse public key saved in local database")
			}
			expectedFingerprint := sshagent.FingerprintSHA256(dbPubKey)

			// Проверяем реальное наличие в ssh-agent ключа, с которым делали init
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "failed to connect to ssh-agent")
			}
			defer agentClient.Close()

			if _, err = agentClient.FindED25519ByFingerprint(expectedFingerprint); err != nil {
				agentErr := fmt.Errorf("the root cryptographic key used during 'init' (%s) must be active in your ssh-agent. Please run 'ssh-add'", expectedFingerprint)
				return cli.PrintError(out, agentErr, "access denied")
			}

			// 4. НАСТРОЙКА СЕТЕВОГО ТРАНСПОРТА (Строго изолированный TLS 1.3 с динамическим Hostname)
			targetHost, _, err := net.SplitHostPort(serverAddr)
			if err != nil {
				targetHost = serverAddr
			}

			// ИСПРАВЛЕНО: Вызываем ваш канонический загрузчик встроенного пула доверия
			serverCAPool, err := certs.LoadServerCAPool()
			if err != nil {
				return cli.PrintError(out, err, "failed to initialize embedded trust store")
			}

			tlsCfg := &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: targetHost,
				RootCAs:    serverCAPool, // Намертво привязываем клиента к нашему Server CA
			}

			conn, err := grpc.NewClient(
				serverAddr,
				grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
			)
			if err != nil {
				return cli.PrintError(out, err, "failed to create gRPC client instance")
			}
			defer conn.Close()

			// Принудительно запускаем немедленный TLS-хендшейк (замена устаревшему WithBlock)
			// Метод вернет ошибку, если имя хоста не совпадет с цепочкой Server CA
			conn.Connect()

			// Ждем установления физического SSL-соединения (Замена WithBlock)
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()

			for {
				state := conn.GetState()
				if state == connectivity.Ready {
					break
				}
				if state == connectivity.TransientFailure || state == connectivity.Shutdown {
					connErr := fmt.Errorf("gRPC secure transport connection failed (state: %s)", state)
					return cli.PrintError(out, connErr, "network error")
				}
				if !conn.WaitForStateChange(ctx, state) {
					timeoutErr := fmt.Errorf("timeout waiting for secure TLS 1.3 handshake to complete")
					return cli.PrintError(out, timeoutErr, "network error")
				}
			}

			// 5. ИНИЦИАЛИЗАЦИЯ СЕРВИСОВ И ЗАПУСК КРИПТОГРАФИЧЕСКОГО КОНВЕЙЕРА (Composition Root)
			initService := service.NewInitService(deviceStore, agentClient)
			regService := service.NewRegisterService(deviceStore, initService, agentClient, conn)

			err = regService.RunRegistration(cmd.Context(), serverAddr)
			if err != nil {
				return cli.PrintError(out, err, "registration pipeline crashed")
			}

			// Выводим финальный результат работы команды
			payload := RegisterResponse{
				UserID:    expectedFingerprint,
				ServerURL: serverAddr,
				Status:    "REGISTERED",
			}

			cli.PrintResult(out, payload, func() {
				fmt.Fprintf(out, "Opening secure TLS 1.3 channel to %s [TLS SNI: %s]...\n", serverAddr, targetHost)
				fmt.Fprintln(out, "Initiating two-step passwordless registration protocol...")
				fmt.Fprintf(out, "\n✔ Success! Device securely bound to account %q on the server.\n", expectedFingerprint)
				fmt.Fprintln(out, "mTLS container certificate received and database status shifted to: REGISTERED")
			})

			return nil
		},
	}

	// Регистрация только нужных эфемерных флагов вызова
	cmd.Flags().String("server", "", "GophKeeper secure server address (HOST:PORT)")

	_ = cmd.MarkFlagRequired("server")

	return cmd
}
