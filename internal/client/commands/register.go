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
		Short: "Привязать локальный сейф к облачному аккаунту через криптографический вызов SSH",
		Long:  `Выполняет двухэтапную авторизацию облачного владения ключом Ed25519 через шифрованный канал TLS 1.3 и импортирует mTLS-паспорт.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			slog.Info("Старт выполнения команды сетевой регистрации устройства")

			// 1. ПРОВЕРКА МАТРИЦЫ PRECONDITIONS
			if err := sshcheck.RequireAgent(); err != nil {
				return cli.PrintError(out, err, "ошибка проверки ssh-agent")
			}

			// Разбираем эфемерные параметры вызова
			flags := cmd.Flags()
			serverAddr, _ := flags.GetString("server")
			serverAddr = strings.TrimSpace(serverAddr)

			if serverAddr == "" {
				return cli.PrintError(out, errors.New("параметр --server обязателен и не может быть пустым"), "валидация флагов")
			}

			// 2. ПРОВЕРКА СОСТОЯНИЯ КОНТЕЙНЕРА (Барьер конечного автомата жизненного цикла)
			app, err := cli.App(cmd.Context())
			if err != nil {
				return cli.PrintError(out, err, "запуск контекста приложения")
			}

			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB())
			localState, err := deviceStore.ReadDeviceState(cmd.Context())
			if err != nil {
				return cli.PrintError(out, err, "чтение локального статуса устройства")
			}

			// Критерий успешной сетевой регистрации — наличие mTLS паспорта устройства
			if localState.ClientCertificate != nil && len(*localState.ClientCertificate) > 0 {
				serverURLStr := "unknown"
				if localState.ServerURL != nil {
					serverURLStr = *localState.ServerURL
				}
				statusErr := fmt.Errorf("контейнер уже зарегистрирован и содержит активный mTLS-паспорт (Сервер: %s, UserID: %s)", serverURLStr, *localState.UserID)
				slog.Warn("Попытка повторной регистрации заблокирована конечным автоматом", "user_id", *localState.UserID)
				return cli.PrintError(out, statusErr, "валидация статуса")
			}

			// 3. РАБОТА С SSH КЛЮЧОМ И АГЕНТОМ
			dbPubKey, err := ssh.ParsePublicKey(localState.SshPublicKey)
			if err != nil {
				return cli.PrintError(out, err, "структура метаданных публичного ключа повреждена")
			}
			expectedFingerprint := sshagent.FingerprintSHA256(dbPubKey)

			// Проверяем реальное наличие в ssh-agent ключа, с которым делали init
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "подключение к сокету ssh-agent")
			}

			agentClosedChecked := false
			defer func() {
				if !agentClosedChecked {
					if closeErr := agentClient.Close(); closeErr != nil {
						slog.Error("Не удалось закрыть UNIX-сокет агента в defer register", "error", closeErr)
					}
				}
			}()

			if _, err = agentClient.FindED25519ByFingerprint(expectedFingerprint); err != nil {
				agentErr := fmt.Errorf("корневой криптографический ключ инициализации (%s) должен быть загружен в ваш ssh-agent. Выполните 'ssh-add'", expectedFingerprint)
				return cli.PrintError(out, agentErr, "отказ в доступе")
			}

			// 4. НАСТРОЙКА СЕТЕВОГО ТРАНСПОРТА (Строго изолированный TLS 1.3 с динамическим Hostname)
			targetHost, _, err := net.SplitHostPort(serverAddr)
			if err != nil {
				targetHost = serverAddr
			}

			serverCAPool, err := certs.LoadServerCAPool()
			if err != nil {
				return cli.PrintError(out, err, "загрузка встроенного пула доверенных сертификатов")
			}

			tlsCfg := &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: targetHost,
				RootCAs:    serverCAPool, // Намертво привязываем клиента к нашему Server CA
			}

			slog.Debug("Открытие изолированного защищенного канала gRPC TLS 1.3", "sni", targetHost)
			conn, err := grpc.NewClient(
				serverAddr,
				grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
			)
			if err != nil {
				return cli.PrintError(out, err, "инициализация сетевого gRPC клиента")
			}

			connClosedChecked := false
			defer func() {
				if !connClosedChecked {
					if closeErr := conn.Close(); closeErr != nil {
						slog.Error("Не удалось закрыть gRPC-соединение в defer register", "error", closeErr)
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
				slog.Debug("Сдвиг состояния gRPC-транспорта авторизации", "state", state.String())

				if state == connectivity.Ready {
					break
				}
				if state == connectivity.TransientFailure || state == connectivity.Shutdown {
					connErr := fmt.Errorf("установление защищенного TLS-канала gRPC прервано (системный статус: %s)", state)
					return cli.PrintError(out, connErr, "сетевой сбой")
				}
				if !conn.WaitForStateChange(ctx, state) {
					timeoutErr := errors.New("таймаут ожидания безопасного рукопожатия TLS 1.3 истек")
					return cli.PrintError(out, timeoutErr, "таймаут сети")
				}
			}

			slog.Info("Физический TLS 1.3 канал успешно верифицирован, запуск Composition Root")

			// 5. ИНИЦИАЛИЗАЦИЯ СЕРВИСОВ И ЗАПУСК КРИПТОГРАФИЧЕСКОГО КОНВЕЙЕРА РЕГИСТРАЦИИ
			initService := service.NewInitService(deviceStore, agentClient)
			regService := service.NewRegisterService(deviceStore, initService, agentClient, conn)

			err = regService.RunRegistration(cmd.Context(), serverAddr)
			if err != nil {
				slog.Error("Криптографический конвейер сетевой регистрации завершился крахом", "error", err)
				return cli.PrintError(out, err, "сбой пайплайна регистрации")
			}

			// Безопасно финализируем ресурсы до вывода результатов на экран
			if closeErr := agentClient.Close(); closeErr != nil {
				slog.Error("Не удалось закрыть сокет агента при успешном выходе из register", "error", closeErr)
			}
			agentClosedChecked = true

			if closeErr := conn.Close(); closeErr != nil {
				slog.Error("Не удалось закрыть транспорт gRPC при успешном выходе из register", "error", closeErr)
			}
			connClosedChecked = true

			// Формируем структурированный payload ответа
			payload := RegisterResponse{
				UserID:    expectedFingerprint,
				ServerURL: serverAddr,
				Status:    "REGISTERED",
			}

			cli.PrintResult(out, payload, func() {
				fmt.Fprintf(out, "Установление канала TLS 1.3 до узла %s [TLS SNI: %s]...\n", serverAddr, targetHost)
				fmt.Fprintln(out, "Запуск двухэтапного беспарольного протокола взаимной верификации...")
				fmt.Fprintf(out, "\n✔ Успех! Контейнер успешно привязан к облачному аккаунту %q.\n", expectedFingerprint)
				fmt.Fprintln(out, "mTLS-паспорт устройства получен и сохранен. Статус изменен на: REGISTERED")
			})

			return nil
		},
	}

	// Регистрация флага вызова
	cmd.Flags().String("server", "", "Адрес доверенного сервера GophKeeper в формате HOST:PORT")
	_ = cmd.MarkFlagRequired("server")

	return cmd
}
