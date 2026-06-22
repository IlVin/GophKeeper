package commands

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	pb "gophkeeper/gen/go/gophkeeper/v1"
	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/domain/security"
	"gophkeeper/internal/shared/certs"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func newSyncCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize local encrypted vault container with GophKeeper cloud",
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()

			app, err := cli.App(ctx)
			if err != nil {
				return cli.PrintError(out, err, "runtime error")
			}

			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB)
			state, err := deviceStore.ReadDeviceState(ctx)
			if err != nil {
				return cli.PrintError(out, err, "failed to read state")
			}

			// Для выполнения sync достаточно иметь валидный адрес сервера, UUID пользователя и mTLS сертификат
			if state.ServerURL == nil || *state.ServerURL == "" || state.ClientCertificate == nil {
				return cli.PrintError(out, fmt.Errorf("container is not registered: please run 'gophkeeper register' first"), "validation failed")
			}

			// =================================================================
			// КРИПТОГРАФИЧЕСКИЙ ВЫВОД КЛЮЧЕЙ И ВСКРЫТИЕ mTLS КЛЮЧА
			// =================================================================

			// 1. Подключаемся к ssh-agent для получения деривационной подписи
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return cli.PrintError(out, err, "connect to ssh-agent")
			}
			defer agentClient.Close()

			dbPubKey, err := ssh.ParsePublicKey(state.SshPublicKey)
			if err != nil {
				return cli.PrintError(out, err, "failed to parse key wire")
			}
			fingerprint := sshagent.FingerprintSHA256(dbPubKey)

			derivationPayload := security.NewDerivationPayload(fingerprint)
			rawDerivationSig, err := agentClient.SignED25519Raw(fingerprint, derivationPayload.Marshal())
			if err != nil {
				return cli.PrintError(out, err, "ssh-agent failed to sign derivation payload")
			}
			derivationSignature := security.SecretBytes(rawDerivationSig)
			defer derivationSignature.Destroy()

			// 2. Выводим AccountUnlockKey
			unlockKey, err := security.DeriveAccountUnlockKey(derivationSignature, state.AccountSalt)
			if err != nil {
				return cli.PrintError(out, err, "failed to derive unlock key")
			}
			defer unlockKey.Destroy()

			// 3. Выводим DeviceKEK на базе DeviceID контейнера
			deviceKEK, err := security.DeriveDeviceKEK(unlockKey, []byte(state.DeviceID))
			if err != nil {
				return cli.PrintError(out, err, "failed to derive device kek")
			}
			defer deviceKEK.Destroy()

			// 4. Расшифровываем MtlsPrivateKey с помощью DeviceKEK
			deviceAAD := security.BuildDeviceMasterKeyAAD(state.UserID, state.DeviceID)

			rawMtlsKeyBytes, err := security.OpenEnvelope(deviceKEK, *state.EncryptedMtlsPrivateKey, deviceAAD)
			if err != nil {
				return cli.PrintError(out, err, "failed to unlock container mTLS private key envelope")
			}
			mtlsSecret := security.SecretBytes(rawMtlsKeyBytes)
			defer mtlsSecret.Destroy()

			// 5. Десериализуем и восстанавливаем ecdsa.PrivateKey
			mtlsPrivKey, err := x509.ParsePKCS8PrivateKey(mtlsSecret)
			if err != nil {
				return cli.PrintError(out, err, "failed to parse decrypted mtls private key")
			}

			// 6. Парсим бинарный x509 DER-сертификат
			x509Cert, err := x509.ParseCertificate(*state.ClientCertificate)
			if err != nil {
				return cli.PrintError(out, err, "failed to parse cached mTLS certificate")
			}

			// Декодируем текстовый PEM встроенного Device CA
			block, _ := pem.Decode(certs.DeviceCAPEM())
			if block == nil || block.Type != "CERTIFICATE" {
				return cli.PrintError(out, fmt.Errorf("failed to decode embedded device ca PEM for mTLS chain"), "crypto error")
			}
			embeddedDeviceCaDER := block.Bytes

			// Конструируем полноценный mTLS паспорт
			clientCert := tls.Certificate{
				Certificate: [][]byte{
					*state.ClientCertificate,
					embeddedDeviceCaDER,
				},
				Leaf:       x509Cert,
				PrivateKey: mtlsPrivKey,
			}

			// =================================================================
			// НАСТРОЙКА mTLS 1.3 КАНАЛА И ЗАПУСК СИНХРОНИЗАЦИИ
			// =================================================================

			serverCAPool, err := certs.LoadServerCAPool()
			if err != nil {
				return cli.PrintError(out, err, "failed to load server ca pool")
			}

			tlsCfg := &tls.Config{
				MinVersion:   tls.VersionTLS13,
				RootCAs:      serverCAPool,
				Certificates: []tls.Certificate{clientCert},
				ServerName:   "localhost",
			}

			conn, err := grpc.NewClient(*state.ServerURL, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
			if err != nil {
				return cli.PrintError(out, err, "network error")
			}
			defer conn.Close()

			syncClient := pb.NewSyncServiceClient(conn)
			secretStore := sqlite.NewSQLiteSecretStore(app.DB)

			// Получаем локальные версии
			localMeta, err := secretStore.GetSyncMetadata(ctx)
			if err != nil {
				return cli.PrintError(out, err, "local store read failed")
			}

			var protoVersions []*pb.RecordVersion
			for id, t := range localMeta {
				protoVersions = append(protoVersions, &pb.RecordVersion{
					RecordId:  id,
					UpdatedAt: t.Format(time.RFC3339),
				})
			}

			// RPC вызов SyncCheck
			checkResp, err := syncClient.SyncCheck(ctx, &pb.SyncCheckRequest{LocalVersions: protoVersions})
			if err != nil {
				return cli.PrintError(out, err, "sync check failed")
			}

			// Исполняем фазу PULL
			pulledCount := 0
			if len(checkResp.GetIdsToPull()) > 0 {
				pullResp, err := syncClient.PullRecords(ctx, &pb.PullRecordsRequest{RecordIds: checkResp.GetIdsToPull()})
				if err != nil {
					return cli.PrintError(out, err, "pull failed")
				}

				for _, r := range pullResp.GetRecords() {
					cTime, _ := time.Parse(time.RFC3339, r.GetCreatedAt())
					uTime, _ := time.Parse(time.RFC3339, r.GetUpdatedAt())

					err = secretStore.SaveRaw(ctx, &repository.EncryptedRecord{
						ID:        r.GetRecordId(),
						Name:      r.GetName(),
						Type:      r.GetType(),
						Envelope:  r.GetEnvelope(),
						CreatedAt: cTime,
						UpdatedAt: uTime,
					})
					if err != nil {
						return cli.PrintError(out, err, "failed to save pulled record")
					}
					pulledCount++
				}
			}

			// Исполняем фазу PUSH
			pushedCount := 0
			if len(checkResp.GetIdsToPush()) > 0 {
				var recordsToPush []*pb.EncryptedRecordPayload
				for _, id := range checkResp.GetIdsToPush() {
					localRec, err := secretStore.GetRawByID(ctx, id)
					if err != nil {
						continue
					}
					recordsToPush = append(recordsToPush, &pb.EncryptedRecordPayload{
						RecordId:  localRec.ID,
						Name:      localRec.Name,
						Type:      localRec.Type,
						Envelope:  localRec.Envelope,
						CreatedAt: localRec.CreatedAt.Format(time.RFC3339),
						UpdatedAt: localRec.UpdatedAt.Format(time.RFC3339),
					})
				}

				if len(recordsToPush) > 0 {
					_, err = syncClient.PushRecords(ctx, &pb.PushRecordsRequest{Records: recordsToPush})
					if err != nil {
						return cli.PrintError(out, err, "push failed")
					}
					pushedCount = len(recordsToPush)
				}
			}

			// Выводим финальный результат работы команды
			payload := SyncResponse{
				Pulled: pulledCount,
				Pushed: pushedCount,
			}

			cli.PrintResult(out, payload, func() {
				fmt.Fprintln(out, "Establishing secure mTLS channel and fetching sync map...")
				fmt.Fprintln(out, "\n✔ Synchronization successful!")
				fmt.Fprintf(out, "  Downloaded from cloud (Pull): %d\n", pulledCount)
				fmt.Fprintf(out, "  Uploaded to cloud     (Push): %d\n", pushedCount)
			})

			return nil
		}),
	}

	return cmd
}
