// Package service содержит компоненты бизнес-логики клиентского приложения GophKeeper,
// оркеструющие криптографические конвейеры, вызовы деривации и сетевую синхронизацию.
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	pb "gophkeeper/gen/go/gophkeeper/v1"
	"gophkeeper/internal/client/providers/device"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/domain/security"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

// RegisterService инкапсулирует сценарий бизнес-логики двухэтапной беспарольной
// регистрации и привязки локального контейнера к облачному аккаунту.
type RegisterService struct {
	deviceStore repository.DeviceStore
	initService *InitService
	agentClient *sshagent.Client
	grpcClient  pb.RegistrationClient
}

// NewRegisterService конструирует новый экземпляр Use-Case сервиса сетевой регистрации.
func NewRegisterService(
	ds repository.DeviceStore,
	is *InitService,
	agent *sshagent.Client,
	conn grpc.ClientConnInterface,
) *RegisterService {
	return &RegisterService{
		deviceStore: ds,
		initService: is,
		agentClient: agent,
		grpcClient:  pb.NewRegistrationClient(conn),
	}
}

// RunRegistration выполняет сквозной защищенный криптографический протокол беспарольной регистрации устройства.
//
// Метод инициирует gRPC-сессию TLS 1.3, проходит криптографический вызов Proof of Possession,
// генерирует mTLS паспорт контейнера P-256 и сверяет локальную соль с серверным каноном (Инварианты №3, №9, №12, №13, №14).
func (s *RegisterService) RunRegistration(ctx context.Context, serverURL string) error {
	slog.Info("Initiating two-step passwordless device cloud registration protocol")

	// 1. Извлекаем текущее локальное состояние устройства из СУБД SQLite
	state, err := s.deviceStore.ReadDeviceState(ctx)
	if err != nil {
		return fmt.Errorf("failed to read initial state: %w", err)
	}

	// ЗАЩИТНЫЙ ИБ-БАРЬЕР: Предотвращает панику разыменования, если база пуста
	if state == nil {
		slog.Warn("Registration pipeline aborted: local container is uninitialized")
		return errors.New("environment is not initialized: please run 'gophkeeper init' first")
	}

	// 2. ВЫЗОВ REGISTER_BEGIN RPC (Передача публичного ключа для идентификации аккаунта)
	slog.Debug("Executing RPC RegisterBegin channel request")
	beginReq := &pb.RegisterBeginRequest{
		SshPublicKey: state.SshPublicKey,
	}
	beginResp, err := s.grpcClient.RegisterBegin(ctx, beginReq)
	if err != nil {
		slog.ErrorContext(context.Background(), "RPC RegisterBegin request failed",
			slog.Any("error", err),
		)
		return fmt.Errorf("gRPC RegisterBegin failed: %w", err)
	}

	// 3. СБОРКА И ПОДПИСЬ КРИПТОГРАФИЧЕСКОГО ЧЕЛЛЕНДЖА
	challenge := security.NewChallengePayload(
		beginResp.GetUserId(),
		beginResp.GetSessionId(),
		beginResp.GetServerNonce(),
		"register",
	)

	pubKey, err := ssh.ParsePublicKey(state.SshPublicKey)
	if err != nil {
		return fmt.Errorf("parse public key failed: %w", err)
	}
	fingerprint := sshagent.FingerprintSHA256(pubKey)

	slog.Debug("Requesting challenge authentication signature from ssh-agent HSM-module")
	authChallengeSignature, err := s.agentClient.SignED25519Raw(fingerprint, challenge.Marshal())
	if err != nil {
		return fmt.Errorf("ssh-agent failed to sign challenge payload: %w", err)
	}

	// 4. ГЕНЕРАЦИЯ mTLS ИДЕНТИЧНОСТИ КОНТЕЙНЕРА (NIST P-256)
	rawMtlsPrivKey, csrBytes, err := device.GenerateContainerCSR(state.DeviceID)
	if err != nil {
		return fmt.Errorf("failed to generate device identity csr: %w", err)
	}

	mtlsSecret := security.SecretBytes(rawMtlsPrivKey)
	defer mtlsSecret.Destroy()

	// 5. ВЫЗОВ REGISTER_FINISH RPC (Передача подписанного челленджа и CSR)
	slog.Debug("Executing RPC RegisterFinish channel request with payload verification tokens")
	finishReq := &pb.RegisterFinishRequest{
		UserId:                   beginResp.GetUserId(),
		SessionId:                beginResp.GetSessionId(),
		AuthChallengeSignature:   authChallengeSignature,
		DeviceId:                 state.DeviceID,
		AccountSalt:              state.AccountSalt,
		AccountBootstrapEnvelope: state.AccountBootstrapEnvelope,
		DeviceMasterKeyEnvelope:  state.DeviceMasterKeyEnvelope,
		Csr:                      csrBytes,
		SshPublicKey:             state.SshPublicKey,
	}

	finishResp, err := s.grpcClient.RegisterFinish(ctx, finishReq)
	if err != nil {
		slog.ErrorContext(context.Background(), "RPC RegisterFinish authentication rejected by cloud server",
			slog.Any("error", err),
		)
		return fmt.Errorf("gRPC RegisterFinish failed: %w", err)
	}

	// 6. КРИТИЧЕСКИЙ СВЕРЯЮЩИЙ БАРЬЕР: СРАВНЕНИЕ С СЕРВЕРНЫМ КАНОНОМ (Last-Write-Wins Инварианты)
	canonicalSalt := finishResp.GetCanonicalAccountSalt()
	canonicalBootstrap := finishResp.GetCanonicalAccountBootstrapEnvelope()

	if !bytes.Equal(state.AccountSalt, canonicalSalt) || !bytes.Equal(state.AccountBootstrapEnvelope, canonicalBootstrap) {
		slog.Info("Server canonical state mismatch detected! Automated local Reconcile Migration triggered.")

		err = s.initService.ReconcileContainer(
			ctx,
			canonicalSalt,
			canonicalBootstrap,
			[]byte(beginResp.GetUserId()),
			finishResp.GetClientCertificate(),
			serverURL,
			mtlsSecret,
		)
		if err != nil {
			slog.ErrorContext(context.Background(), "Automated local reconciliation migration collapsed",
				slog.Any("error", err),
			)
			return fmt.Errorf("local reconcile migration failed: %w", err)
		}

		slog.Info("Device successfully linked and migrated under canonical server credentials via Reconcile")
		return nil
	}

	// 7. ЕСЛИ СВЕРКА ПРОШЛА УСПЕШНО (Мы являемся первичным контейнером аккаунта в облаке)
	slog.Debug("Local credentials match cloud canon, deriving DeviceKEK for client certificate sealing")
	derivationPayload := security.NewDerivationPayload(fingerprint)
	rawDerivationSig, err := s.agentClient.SignED25519Raw(fingerprint, derivationPayload.Marshal())
	if err != nil {
		return fmt.Errorf("failed to obtain derivation signature for mtls isolation: %w", err)
	}
	derivationSignature := security.SecretBytes(rawDerivationSig)
	defer derivationSignature.Destroy()

	unlockKey, err := security.DeriveAccountUnlockKey(derivationSignature, state.AccountSalt)
	if err != nil {
		return err
	}
	defer unlockKey.Destroy()

	deviceKEK, err := security.DeriveDeviceKEK(unlockKey, []byte(state.DeviceID))
	if err != nil {
		return err
	}
	defer deviceKEK.Destroy()

	userIDStr := beginResp.GetUserId()
	deviceAAD := security.BuildDeviceMasterKeyAAD(&userIDStr, state.DeviceID)

	// Запечатываем mTLS приватный ключ под локальным DeviceKEK для персистентного хранения в SQLite
	encryptedMtlsJSON, err := security.SealEnvelope(deviceKEK, mtlsSecret, deviceAAD, security.AADSchemaDeviceMasterKey)
	if err != nil {
		return fmt.Errorf("failed to seal mtls private key under device kek: %w", err)
	}

	clientCertBytes := finishResp.GetClientCertificate()

	updatedState := &repository.LocalDeviceState{
		ServerURL:                &serverURL,
		UserID:                   &userIDStr,
		DeviceID:                 state.DeviceID,
		SshPublicKey:             state.SshPublicKey,
		AccountSalt:              state.AccountSalt,
		AccountBootstrapEnvelope: state.AccountBootstrapEnvelope,
		DeviceMasterKeyEnvelope:  state.DeviceMasterKeyEnvelope,
		EncryptedMtlsPrivateKey:  &encryptedMtlsJSON,
		ClientCertificate:        &clientCertBytes,
		CreatedAt:                state.CreatedAt,
	}

	slog.Debug("Committing final registered device state container metadata to SQLite")
	if err := s.deviceStore.SaveDeviceState(ctx, updatedState); err != nil {
		return fmt.Errorf("failed to commit registered state to database: %w", err)
	}

	slog.Info("Device registration process finalized successfully. Passport mTLS verified.")
	return nil
}
