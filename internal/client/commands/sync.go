// Package commands предоставляет реализации консольных команд Cobra для
// криптографического взаимодействия с хранилищем GophKeeper.
package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"

	pb "gophkeeper/gen/go/gophkeeper/v1"
	clientapp "gophkeeper/internal/client/app"
	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/domain/security"
	"gophkeeper/internal/shared/certs"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// newSyncCommand конструирует CLI-команду "sync" для проведения двусторонней
// криптографически безопасной репликации данных между клиентом и облаком GophKeeper.
func newSyncCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Синхронизировать локальный зашифрованный сейф с облачным хранилищем",
		Long:  `Выполняет сверку версий по протоколу LWW (Last-Write-Wins), скачивает свежие облачные конверты и публикует локальные изменения через защищенный mTLS 1.3 канал.`,
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			slog.Info("Старт сквозного процесса синхронизации данных с облаком")

			app, err := cli.App(ctx)
			if err != nil {
				return cli.PrintError(out, err, "ошибка рантайма приложения")
			}

			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB())
			state, err := deviceStore.ReadDeviceState(ctx)
			if err != nil {
				return cli.PrintError(out, err, "чтение локального состояния контейнера")
			}

			// Проверка инварианта сетевой готовности: для выполнения sync необходим активный mTLS-паспорт
			if state.ServerURL == nil || *state.ServerURL == "" || state.ClientCertificate == nil || state.EncryptedMtlsPrivateKey == nil {
				statusErr := errors.New("контейнер не связан с сервером: пожалуйста, выполните сначала команду 'gophkeeper register'")
				slog.Warn("Попытка синхронизации отклонена: отсутствует mTLS-паспорт устройства")
				return cli.PrintError(out, statusErr, "ошибка валидации")
			}

			// =================================================================
			// КРИПТОГРАФИЧЕСКИЙ ВЫВОД КЛЮЧЕЙ И ВСКРЫТИЕ mTLS КЛЮЧА
			// =================================================================
			slog.Debug("Запуск криптографического конвейера извлечения mTLS-паспорта из контейнера")

			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "подключение к сокету ssh-agent")
			}

			agentClosedChecked := false
			defer func() {
				if !agentClosedChecked {
					if closeErr := agentClient.Close(); closeErr != nil {
						slog.Error("Не удалось закрыть UNIX-сокет агента в defer sync", "error", closeErr)
					}
				}
			}()

			dbPubKey, err := ssh.ParsePublicKey(state.SshPublicKey)
			if err != nil {
				return cli.PrintError(out, err, "структура публичного ключа СУБД повреждена")
			}
			fingerprint := sshagent.FingerprintSHA256(dbPubKey)

			derivationPayload := security.NewDerivationPayload(fingerprint)
			rawDerivationSig, err := agentClient.SignED25519Raw(fingerprint, derivationPayload.Marshal())
			if err != nil {
				return cli.PrintError(out, err, "ssh-agent отклонил подпись payload деривации")
			}
			derivationSignature := security.SecretBytes(rawDerivationSig)
			defer derivationSignature.Destroy()

			// Вывод AccountUnlockKey и DeviceKEK
			unlockKey, err := security.DeriveAccountUnlockKey(derivationSignature, state.AccountSalt)
			if err != nil {
				return cli.PrintError(out, err, "вывод ключа разблокировки аккаунта")
			}
			defer unlockKey.Destroy()

			deviceKEK, err := security.DeriveDeviceKEK(unlockKey, []byte(state.DeviceID))
			if err != nil {
				return cli.PrintError(out, err, "вывод симметричного ключа устройства DeviceKEK")
			}
			defer deviceKEK.Destroy()

			// Расшифровываем MtlsPrivateKey с помощью DeviceKEK с проверкой целостности AAD
			deviceAAD := security.BuildDeviceMasterKeyAAD(state.UserID, state.DeviceID)
			rawMtlsKeyBytes, err := security.OpenEnvelope(deviceKEK, *state.EncryptedMtlsPrivateKey, deviceAAD)
			if err != nil {
				return cli.PrintError(out, err, "криптографическое вскрытие конверта mTLS приватного ключа провалено (泄露/tampering)")
			}
			mtlsSecret := security.SecretBytes(rawMtlsKeyBytes)
			defer mtlsSecret.Destroy()

			// Десериализуем ecdsa.PrivateKey из стандарта PKCS#8
			parsedPrivKey, err := x509.ParsePKCS8PrivateKey(mtlsSecret)
			if err != nil {
				return cli.PrintError(out, err, "структура расшифрованного mTLS приватного ключа некорректна")
			}
			mtlsPrivKey, ok := parsedPrivKey.(*ecdsa.PrivateKey)
			if !ok {
				return cli.PrintError(out, errors.New("mTLS закрытый ключ не принадлежит семейству эллиптических кривых ECDSA"), "криптографическая ошибка")
			}

			// ГАРАНТИЯ ИБ (RAM Hygiene): Обеспечиваем тотальное зануление больших чисел закрытого ключа в куче Go
			defer func() {
				if mtlsPrivKey != nil && mtlsPrivKey.D != nil {
					mtlsPrivKey.D.SetInt64(0)
					mtlsPrivKey.D = big.NewInt(0)
				}
				slog.Debug("Структура приватного ключа ECDSA полностью обнулена в памяти (RAM Hygiene)")
			}()

			// Восстановление цепочки x509 DER-сертификата
			x509Cert, err := x509.ParseCertificate(*state.ClientCertificate)
			if err != nil {
				return cli.PrintError(out, err, "cached x509 DER паспорт устройства поврежден")
			}

			block, _ := pem.Decode(certs.DeviceCAPEM())
			if block == nil || block.Type != "CERTIFICATE" {
				return cli.PrintError(out, errors.New("не удалось декодировать встроенный Device CA PEM для mTLS цепочки доверия"), "криптографическая ошибка")
			}

			clientCert := tls.Certificate{
				Certificate: [][]byte{
					*state.ClientCertificate,
					block.Bytes,
				},
				Leaf:       x509Cert,
				PrivateKey: mtlsPrivKey,
			}

			// Вызов второй половины алгоритма (Сетевой стек и синхронизация)
			return executeNetworkSync(ctx, out, cli, state, agentClient, &agentClosedChecked, clientCert, app)
		}),
	}

	return cmd
}

// executeNetworkSync инкапсулирует mTLS 1.3 подключение и пошаговый конвейер LWW-синхронизации.
func executeNetworkSync(
	ctx context.Context,
	out io.Writer,
	cli *CLI,
	state *repository.LocalDeviceState,
	agentClient *sshagent.Client,
	agentClosedChecked *bool,
	clientCert tls.Certificate,
	app *clientapp.App,
) error {
	// =================================================================
	// НАСТРОЙКА mTLS 1.3 КАНАЛА И ЗАПУСК СИНХРОНИЗАЦИИ
	// =================================================================
	serverCAPool, err := certs.LoadServerCAPool()
	if err != nil {
		return cli.PrintError(out, err, "загрузка пула Server CA")
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      serverCAPool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "localhost",
	}

	slog.Debug("Установление защищенной mTLS 1.3 gRPC сессии синхронизации", "url", *state.ServerURL)
	conn, err := grpc.NewClient(
		*state.ServerURL,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxCallMsgSize),
			grpc.MaxCallSendMsgSize(maxCallMsgSize),
		),
	)
	if err != nil {
		return cli.PrintError(out, err, "сетевое подключение к gRPC узлу синхронизации")
	}

	connClosedChecked := false
	defer func() {
		if !connClosedChecked {
			if closeErr := conn.Close(); closeErr != nil {
				slog.Error("Не удалось закрыть gRPC соединение в defer sync", "error", closeErr)
			}
		}
	}()

	syncClient := pb.NewSyncServiceClient(conn)
	secretStore := sqlite.NewSQLiteSecretStore(app.DB())

	// Извлекаем карту версий локальных секретов
	localMeta, err := secretStore.GetSyncMetadataWithDeleted(ctx)
	if err != nil {
		return cli.PrintError(out, err, "чтение карты версий из локального SQLite")
	}

	var protoVersions []*pb.RecordVersion
	for id, meta := range localMeta {
		protoVersions = append(protoVersions, &pb.RecordVersion{
			RecordId:  id,
			UpdatedAt: timestamppb.New(meta.UpdatedAt),
			IsDeleted: meta.IsDeleted,
		})
	}

	// Сетевой вызов SyncCheck (Сверка версий Last-Write-Wins)
	slog.Debug("RPC Вызов SyncCheck: отправка локальной карты версий в облако", "count", len(protoVersions))
	checkResp, err := syncClient.SyncCheck(ctx, &pb.SyncCheckRequest{LocalVersions: protoVersions})
	if err != nil {
		return cli.PrintError(out, err, "удаленный вызов SyncCheck провален")
	}

	// Безопасно финализируем сокет агента, так как криптооперации деривации завершены
	if closeErr := agentClient.Close(); closeErr != nil {
		slog.Error("Не удалось закрыть UNIX-сокет агента в процессе обмена", "error", closeErr)
	}
	*agentClosedChecked = true

	// ФАЗА 1: PULL (Скачивание свежих данных из облака)
	pulledCount := 0
	idsToPull := checkResp.GetIdsToPull()
	if len(idsToPull) > 0 {
		slog.Debug("Обнаружены устаревшие локальные записи, инициирован RPC PullRecords", "count", len(idsToPull))
		pullResp, err := syncClient.PullRecords(ctx, &pb.PullRecordsRequest{RecordIds: idsToPull})
		if err != nil {
			return cli.PrintError(out, err, "удаленная фаза PullRecords отклонена сервером")
		}

		for _, r := range pullResp.GetRecords() {
			// Даты извлекаются нативно через .AsTime() без риска Scan Errors
			if r.GetCreatedAt() == nil || r.GetUpdatedAt() == nil {
				slog.Error("Сервер прислал пустой блок Timestamp для pulled записи, пакет пропущен", "record_id", r.GetRecordId())
				continue
			}

			cTime := r.GetCreatedAt().AsTime().UTC()
			uTime := r.GetUpdatedAt().AsTime().UTC()

			err = secretStore.SaveRaw(ctx, &repository.EncryptedRecord{
				ID:        r.GetRecordId(),
				Name:      r.GetName(),
				Type:      r.GetType(),
				Envelope:  r.GetEnvelope(),
				CreatedAt: cTime,
				UpdatedAt: uTime,
				IsDeleted: r.GetIsDeleted(),
			})
			if err != nil {
				slog.Error("Не удалось сохранить выкачанный конверт в SQLite", "record_id", r.GetRecordId(), "error", err)
				return cli.PrintError(out, err, "сохранение pulled записи в хранилище")
			}
			pulledCount++
		}
	}

	// ФАЗА 2: PUSH (Закачивание свежих оффлайн-изменений в облако)
	pushedCount := 0
	idsToPush := checkResp.GetIdsToPush()
	if len(idsToPush) > 0 {
		slog.Debug("Обнаружены свежие оффлайн-изменения, сборка пакета для RPC PushRecords", "count", len(idsToPush))
		var recordsToPush []*pb.EncryptedRecordPayload

		for _, id := range idsToPush {
			localRec, err := secretStore.GetRawByID(ctx, id)
			if err != nil {
				slog.Error("Не удалось извлечь сырой конверт для push", "id", id, "error", err)
				continue
			}

			recordsToPush = append(recordsToPush, &pb.EncryptedRecordPayload{
				RecordId:  localRec.ID,
				Name:      localRec.Name,
				Type:      localRec.Type,
				Envelope:  localRec.Envelope,
				CreatedAt: timestamppb.New(localRec.CreatedAt),
				UpdatedAt: timestamppb.New(localRec.UpdatedAt),
				IsDeleted: localRec.IsDeleted,
			})
		}

		if len(recordsToPush) > 0 {
			_, err = syncClient.PushRecords(ctx, &pb.PushRecordsRequest{Records: recordsToPush})
			if err != nil {
				return cli.PrintError(out, err, "удаленная фаза PushRecords отклонена сервером")
			}
			pushedCount = len(recordsToPush)
		}
	}

	// Безопасно закрываем сетевой канал gRPC до рендеринга вывода
	if closeErr := conn.Close(); closeErr != nil {
		slog.Error("Не удалось закрыть gRPC транспорт при чистом выходе из sync", "error", closeErr)
	}
	connClosedChecked = true

	payload := SyncResponse{
		Pulled: pulledCount,
		Pushed: pushedCount,
	}

	cli.PrintResult(out, payload, func() {
		fmt.Fprintln(out, "Установление mTLS 1.3 сессии и сверка карт синхронизации...")
		fmt.Fprintln(out, "\n✔ Двусторонняя синхронизация завершена успешно!")
		fmt.Fprintf(out, "  Скачано изменений из облака (Pull): %d\n", pulledCount)
		fmt.Fprintf(out, "  Загружено оффлайн-записей в облако (Push): %d\n", pushedCount)
	})

	return nil
}
