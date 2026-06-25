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
		Short: "Synchronize local encrypted vault with cloud storage",
		Long:  `Performs LWW (Last-Write-Wins) version reconciliation, downloads fresh cloud envelopes and publishes local changes via secure mTLS 1.3 channel.`,
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()
			slog.Info("Starting end-to-end cloud data synchronization process")

			app, err := cli.App(ctx)
			if err != nil {
				return cli.PrintError(out, err, "application runtime error")
			}

			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB())
			state, err := deviceStore.ReadDeviceState(ctx)
			if err != nil {
				return cli.PrintError(out, err, "reading local container state")
			}

			// Проверка инварианта сетевой готовности: для выполнения sync необходим активный mTLS-паспорт
			if state.ServerURL == nil || *state.ServerURL == "" || state.ClientCertificate == nil || state.EncryptedMtlsPrivateKey == nil {
				statusErr := errors.New("container not linked to server: please run .gophkeeper register. first")
				slog.Warn("Sync attempt rejected: missing device mTLS passport")
				return cli.PrintError(out, statusErr, "validation error")
			}

			// =================================================================
			// КРИПТОГРАФИЧЕСКИЙ ВЫВОД КЛЮЧЕЙ И ВСКРЫТИЕ mTLS КЛЮЧА
			// =================================================================
			slog.Debug("Starting cryptographic pipeline for mTLS passport extraction from container")

			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "connect to ssh-agent socket")
			}

			agentClosedChecked := false
			defer func() {
				if !agentClosedChecked {
					if closeErr := agentClient.Close(); closeErr != nil {
						slog.ErrorContext(context.Background(), "Failed to close UNIX agent socket in sync defer",
							slog.Any("error", closeErr),
						)
					}
				}
			}()

			dbPubKey, err := ssh.ParsePublicKey(state.SshPublicKey)
			if err != nil {
				return cli.PrintError(out, err, "DB public key structure corrupted")
			}
			fingerprint := sshagent.FingerprintSHA256(dbPubKey)

			derivationPayload := security.NewDerivationPayload(fingerprint)
			rawDerivationSig, err := agentClient.SignED25519Raw(fingerprint, derivationPayload.Marshal())
			if err != nil {
				return cli.PrintError(out, err, "ssh-agent rejected derivation payload signing")
			}
			derivationSignature := security.SecretBytes(rawDerivationSig)
			defer derivationSignature.Destroy()

			// Вывод AccountUnlockKey и DeviceKEK
			unlockKey, err := security.DeriveAccountUnlockKey(derivationSignature, state.AccountSalt)
			if err != nil {
				return cli.PrintError(out, err, "account unlock key derivation")
			}
			defer unlockKey.Destroy()

			deviceKEK, err := security.DeriveDeviceKEK(unlockKey, []byte(state.DeviceID))
			if err != nil {
				return cli.PrintError(out, err, "device symmetric key DeviceKEK derivation")
			}
			defer deviceKEK.Destroy()

			// Расшифровываем MtlsPrivateKey с помощью DeviceKEK с проверкой целостности AAD
			deviceAAD := security.BuildDeviceMasterKeyAAD(state.UserID, state.DeviceID)
			rawMtlsKeyBytes, err := security.OpenEnvelope(deviceKEK, *state.EncryptedMtlsPrivateKey, deviceAAD)
			if err != nil {
				return cli.PrintError(out, err, "cryptographic opening of mTLS private key envelope failed (泄露/tampering)")
			}
			mtlsSecret := security.SecretBytes(rawMtlsKeyBytes)
			defer mtlsSecret.Destroy()

			// Десериализуем ecdsa.PrivateKey из стандарта PKCS#8
			parsedPrivKey, err := x509.ParsePKCS8PrivateKey(mtlsSecret)
			if err != nil {
				return cli.PrintError(out, err, "decrypted mTLS private key structure invalid")
			}
			mtlsPrivKey, ok := parsedPrivKey.(*ecdsa.PrivateKey)
			if !ok {
				return cli.PrintError(out, errors.New("mTLS private key is not of ECDSA elliptic curve family"), "cryptographic error")
			}

			// ГАРАНТИЯ ИБ (RAM Hygiene): Обеспечиваем тотальное зануление больших чисел закрытого ключа в куче Go
			defer func() {
				if mtlsPrivKey != nil && mtlsPrivKey.D != nil {
					mtlsPrivKey.D.SetInt64(0)
					mtlsPrivKey.D = big.NewInt(0)
				}
				slog.Debug("ECDSA private key structure fully zeroed in memory (RAM Hygiene)")
			}()

			// Восстановление цепочки x509 DER-сертификата
			x509Cert, err := x509.ParseCertificate(*state.ClientCertificate)
			if err != nil {
				return cli.PrintError(out, err, "cached x509 DER device passport corrupted")
			}

			block, _ := pem.Decode(certs.DeviceCAPEM())
			if block == nil || block.Type != "CERTIFICATE" {
				return cli.PrintError(out, errors.New("failed to decode embedded Device CA PEM for mTLS trust chain"), "cryptographic error")
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
		return cli.PrintError(out, err, "loading Server CA pool")
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      serverCAPool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "localhost",
	}

	slog.Debug("Establishing secure mTLS 1.3 gRPC sync session",
		slog.String("url", *state.ServerURL),
	)
	conn, err := grpc.NewClient(
		*state.ServerURL,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxCallMsgSize),
			grpc.MaxCallSendMsgSize(maxCallMsgSize),
		),
	)
	if err != nil {
		return cli.PrintError(out, err, "network connection to gRPC sync node")
	}

	connClosedChecked := false
	defer func() {
		if !connClosedChecked {
			if closeErr := conn.Close(); closeErr != nil {
				slog.ErrorContext(context.Background(), "Failed to close gRPC connection in sync defer",
					slog.Any("error", closeErr),
				)
			}
		}
	}()

	syncClient := pb.NewSyncServiceClient(conn)
	secretStore := sqlite.NewSQLiteSecretStore(app.DB())

	// Извлекаем карту версий локальных секретов
	localMeta, err := secretStore.GetSyncMetadataWithDeleted(ctx)
	if err != nil {
		return cli.PrintError(out, err, "reading version map from local SQLite")
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
	slog.Debug("RPC SyncCheck call: sending local version map to cloud",
		slog.Int("count", len(protoVersions)),
	)
	checkResp, err := syncClient.SyncCheck(ctx, &pb.SyncCheckRequest{LocalVersions: protoVersions})
	if err != nil {
		return cli.PrintError(out, err, "remote SyncCheck call failed")
	}

	// Безопасно финализируем сокет агента, так как криптооперации деривации завершены
	if closeErr := agentClient.Close(); closeErr != nil {
		slog.ErrorContext(context.Background(), "Failed to close UNIX agent socket during exchange",
			slog.Any("error", closeErr),
		)
	}
	*agentClosedChecked = true

	// ФАЗА 1: PULL (Скачивание свежих данных из облака)
	pulledCount := 0
	idsToPull := checkResp.GetIdsToPull()
	if len(idsToPull) > 0 {
		slog.Debug("Outdated local records found, initiating RPC PullRecords",
			slog.Int("count", len(idsToPull)),
		)
		pullResp, err := syncClient.PullRecords(ctx, &pb.PullRecordsRequest{RecordIds: idsToPull})
		if err != nil {
			return cli.PrintError(out, err, "remote PullRecords phase rejected by server")
		}

		for _, r := range pullResp.GetRecords() {
			// Даты извлекаются нативно через .AsTime() без риска Scan Errors
			if r.GetCreatedAt() == nil || r.GetUpdatedAt() == nil {
				slog.ErrorContext(context.Background(), "Server sent empty Timestamp block for pulled record, packet skipped",
					slog.String("record_id", r.GetRecordId()),
				)
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
				slog.ErrorContext(context.Background(), "Failed to save pulled envelope to SQLite",
					slog.String("record_id", r.GetRecordId()),
					slog.Any("error", err),
				)
				return cli.PrintError(out, err, "saving pulled record to storage")
			}
			pulledCount++
		}
	}

	// ФАЗА 2: PUSH (Закачивание свежих оффлайн-изменений в облако)
	pushedCount := 0
	idsToPush := checkResp.GetIdsToPush()
	if len(idsToPush) > 0 {
		slog.Debug("Fresh offline changes found, building packet for RPC PushRecords",
			slog.Int("count", len(idsToPush)),
		)
		var recordsToPush []*pb.EncryptedRecordPayload

		for _, id := range idsToPush {
			localRec, err := secretStore.GetRawByID(ctx, id)
			if err != nil {
				slog.ErrorContext(context.Background(), "Failed to extract raw envelope for push",
					slog.String("id", id),
					slog.Any("error", err),
				)
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
				return cli.PrintError(out, err, "remote PushRecords phase rejected by server")
			}
			pushedCount = len(recordsToPush)
		}
	}

	// Безопасно закрываем сетевой канал gRPC до рендеринга вывода
	if closeErr := conn.Close(); closeErr != nil {
		slog.ErrorContext(context.Background(), "Failed to close gRPC transport on clean sync exit",
			slog.Any("error", closeErr),
		)
	}
	connClosedChecked = true

	payload := SyncResponse{
		Pulled: pulledCount,
		Pushed: pushedCount,
	}

	cli.PrintResult(out, payload, func() {
		fmt.Fprintln(out, "Establishing mTLS 1.3 session and sync map reconciliation...")
		fmt.Fprintln(out, "\n[OK] Two-way synchronization completed successfully!")
		fmt.Fprintf(out, "  Pulled changes from cloud (Pull): %d\n", pulledCount)
		fmt.Fprintf(out, "  Pushed offline records to cloud (Push): %d\n", pushedCount)
	})

	return nil
}
