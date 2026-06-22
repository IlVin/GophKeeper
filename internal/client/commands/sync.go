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
		//withOwnerCheck middleware гарантирует, что чужой ключ не вызовет команду
		RunE: cli.withOwnerCheck(func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := cmd.Context()

			app, err := cli.App(ctx)
			if err != nil {
				return fmt.Errorf("runtime error: %w", err)
			}

			deviceStore := sqlite.NewSQLiteDeviceStore(app.DB)
			state, err := deviceStore.ReadDeviceState(ctx)
			if err != nil {
				return fmt.Errorf("failed to read state: %w", err)
			}

			if state.ServerURL == nil || *state.ServerURL == "" || state.ClientCertificate == nil || state.EncryptedMtlsPrivateKey == nil {
				return fmt.Errorf("container is not registered: please run 'gophkeeper register' first")
			}

			// =================================================================
			// КРИПТОГРАФИЧЕСКИЙ ВЫВОД КЛЮЧЕЙ И ВСКРЫТИЕ mTLS КЛЮЧА (Инвариант №9)
			// =================================================================

			// 1. Подключаемся к ssh-agent для получения деривационной подписи
			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return fmt.Errorf("connect to ssh-agent: %w", err)
			}
			defer agentClient.Close()

			dbPubKey, err := ssh.ParsePublicKey(state.SshPublicKey)
			if err != nil {
				return fmt.Errorf("failed to parse key wire: %w", err)
			}
			fingerprint := sshagent.FingerprintSHA256(dbPubKey)

			derivationPayload := security.NewDerivationPayload(fingerprint)
			rawDerivationSig, err := agentClient.SignED25519Raw(fingerprint, derivationPayload.Marshal())
			if err != nil {
				return fmt.Errorf("ssh-agent failed to sign derivation payload: %w", err)
			}
			derivationSignature := security.SecretBytes(rawDerivationSig)
			defer derivationSignature.Destroy()

			// 2. Выводим AccountUnlockKey
			unlockKey, err := security.DeriveAccountUnlockKey(derivationSignature, state.AccountSalt)
			if err != nil {
				return fmt.Errorf("failed to derive unlock key: %w", err)
			}
			defer unlockKey.Destroy()

			// 3. Выводим DeviceKEK на базе DeviceID контейнера
			deviceKEK, err := security.DeriveDeviceKEK(unlockKey, []byte(state.DeviceID))
			if err != nil {
				return fmt.Errorf("failed to derive device kek: %w", err)
			}
			defer deviceKEK.Destroy()

			// 4. Расшифровываем MtlsPrivateKey с помощью DeviceKEK (Слепое вскрытие пакета)
			deviceAAD := security.BuildDeviceMasterKeyAAD(state.UserID, state.DeviceID)

			// ИСПРАВЛЕНО: Удален лишний четвертый строковый аргумент, мешавший компиляции
			rawMtlsKeyBytes, err := security.OpenEnvelope(deviceKEK, *state.EncryptedMtlsPrivateKey, deviceAAD)
			if err != nil {
				return fmt.Errorf("failed to unlock container mTLS private key envelope: %w", err)
			}
			mtlsSecret := security.SecretBytes(rawMtlsKeyBytes)
			defer mtlsSecret.Destroy()

			// 5. Десериализуем и восстанавливаем ecdsa.PrivateKey из стандарта PKCS#8
			mtlsPrivKey, err := x509.ParsePKCS8PrivateKey(mtlsSecret)
			if err != nil {
				return fmt.Errorf("failed to parse decrypted mtls private key: %w", err)
			}

			// 6. Парсим бинарный x509 DER-сертификат
			x509Cert, err := x509.ParseCertificate(*state.ClientCertificate)
			if err != nil {
				return fmt.Errorf("failed to parse cached mTLS certificate: %w", err)
			}

			// Декодируем текстовый PEM встроенного Device CA в сырые бинарные байты ASN.1 DER
			block, _ := pem.Decode(certs.DeviceCAPEM())
			if block == nil || block.Type != "CERTIFICATE" {
				return fmt.Errorf("failed to decode embedded device ca PEM for mTLS chain")
			}
			embeddedDeviceCaDER := block.Bytes

			// Конструируем полноценный mTLS паспорт для рантайма сетевого TLS Go
			clientCert := tls.Certificate{
				Certificate: [][]byte{
					*state.ClientCertificate,
					embeddedDeviceCaDER,
				},
				Leaf:       x509Cert,
				PrivateKey: mtlsPrivKey, // Теперь приватный ключ на месте!
			}

			// =================================================================
			// НАСТРОЙКА mTLS 1.3 КАНАЛА И ЗАПУСК СИНХРОНИЗАЦИИ
			// =================================================================

			serverCAPool, err := certs.LoadServerCAPool()
			if err != nil {
				return err
			}

			tlsCfg := &tls.Config{
				MinVersion:   tls.VersionTLS13,
				RootCAs:      serverCAPool,
				Certificates: []tls.Certificate{clientCert},
				ServerName:   "localhost", // SNI валидация хоста
			}

			conn, err := grpc.NewClient(*state.ServerURL, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
			if err != nil {
				return fmt.Errorf("network error: %w", err)
			}
			defer conn.Close()

			syncClient := pb.NewSyncServiceClient(conn)
			secretStore := sqlite.NewSQLiteSecretStore(app.DB)

			fmt.Fprintln(out, "Establishing secure mTLS channel and fetching sync map...")

			// Получаем локальные версии
			localMeta, err := secretStore.GetSyncMetadata(ctx)
			if err != nil {
				return fmt.Errorf("local store read failed: %w", err)
			}

			var protoVersions []*pb.RecordVersion
			for id, t := range localMeta {
				protoVersions = append(protoVersions, &pb.RecordVersion{
					RecordId:  id,
					UpdatedAt: t.Format(time.RFC3339),
				})
			}

			// RPC вызов SyncCheck (LWW верификация)
			checkResp, err := syncClient.SyncCheck(ctx, &pb.SyncCheckRequest{LocalVersions: protoVersions})
			if err != nil {
				return fmt.Errorf("sync check failed: %w", err)
			}

			// Исполняем фазу PULL
			pulledCount := 0
			if len(checkResp.GetIdsToPull()) > 0 {
				pullResp, err := syncClient.PullRecords(ctx, &pb.PullRecordsRequest{RecordIds: checkResp.GetIdsToPull()})
				if err != nil {
					return fmt.Errorf("pull failed: %w", err)
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
						return fmt.Errorf("failed to save pulled record: %w", err)
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
						return fmt.Errorf("push failed: %w", err)
					}
					pushedCount = len(recordsToPush)
				}
			}

			fmt.Fprintln(out, "\n✔ Synchronization successful!")
			fmt.Fprintf(out, "  Downloaded from cloud (Pull): %d\n", pulledCount)
			fmt.Fprintf(out, "  Uploaded to cloud     (Push): %d\n", pushedCount)

			return nil
		}),
	}

	return cmd
}
