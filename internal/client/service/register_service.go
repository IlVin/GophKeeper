package service

import (
	"bytes"
	"context"
	"fmt"
	"os"

	pb "gophkeeper/gen/go/gophkeeper/v1" // Путь сгенерированных Go-заглушек
	"gophkeeper/internal/client/providers/device"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/domain/security"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

type RegisterService struct {
	deviceStore repository.DeviceStore
	initService *InitService // Ссылка на сервис, выполняющий ReconcileContainer
	agentClient *sshagent.Client
	grpcClient  pb.RegistrationClient
}

// NewRegisterService конструирует use-case сервис регистрации устройства.
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

// RunRegistration выполняет сквозной двухэтапный сценарий беспарольной регистрации устройства.
func (s *RegisterService) RunRegistration(ctx context.Context, serverURL string) error {
	// 1. Вычитываем текущее локальное INITIALIZED состояние устройства из SQLite
	state, err := s.deviceStore.ReadDeviceState(ctx)
	if err != nil {
		return fmt.Errorf("failed to read initial state: %w", err)
	}

	// 2. ВЫЗОВ REGISTER_BEGIN RPC (Через чистый TLS 1.3)
	beginReq := &pb.RegisterBeginRequest{
		SshPublicKey: state.SshPublicKey,
	}
	beginResp, err := s.grpcClient.RegisterBegin(ctx, beginReq)
	if err != nil {
		return fmt.Errorf("gRPC RegisterBegin failed: %w", err)
	}

	// 3. СБОРКА И ПОДПИСЬ ЧЕЛЛЕНДЖА (Инвариант №3: Разделение ролей подписей)
	challenge := security.NewChallengePayload(
		beginResp.GetUserId(),
		beginResp.GetSessionId(),
		beginResp.GetServerNonce(),
		"register",
	)

	// Извлекаем фингерпринт из локального состояния для идентификации ключа в агенте
	pubKey, err := ssh.ParsePublicKey(state.SshPublicKey)
	if err != nil {
		return fmt.Errorf("parse public key failed: %w", err)
	}
	fingerprint := sshagent.FingerprintSHA256(pubKey)

	// Запрашиваем AuthChallengeSignature у агента (Payload содержит UserID, SessionID и ServerNonce)
	authChallengeSignature, err := s.agentClient.SignED25519Raw(fingerprint, challenge.Marshal())
	if err != nil {
		return fmt.Errorf("ssh-agent failed to sign challenge payload: %w", err)
	}

	// 4. ГЕНЕРАЦИЯ mTLS ИДЕНТИЧНОСТИ КОНТЕЙНЕРА
	rawMtlsPrivKey, csrBytes, err := device.GenerateContainerCSR(state.DeviceID)
	if err != nil {
		return fmt.Errorf("failed to generate device identity csr: %w", err)
	}
	mtlsSecret := security.SecretBytes(rawMtlsPrivKey)
	defer mtlsSecret.Destroy()

	// 5. ВЫЗОВ REGISTER_FINISH RPC
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
		return fmt.Errorf("gRPC RegisterFinish failed: %w", err)
	}

	// 6. КРИТИЧЕСКИЙ СВЕРЯЮЩИЙ БАРЬЕР: СРАВНЕНИЕ С СЕРВЕРНЫМ КАНОНОМ (Инвариант №12, №13)
	canonicalSalt := finishResp.GetCanonicalAccountSalt()
	canonicalBootstrap := finishResp.GetCanonicalAccountBootstrapEnvelope()

	if !bytes.Equal(state.AccountSalt, canonicalSalt) || !bytes.Equal(state.AccountBootstrapEnvelope, canonicalBootstrap) {
		// Обнаружено несовпадение: контейнер был создан оффлайн со своей солью, но сервер вернул каноничную соль!
		// Запускаем криптографический конвейер Reconcile Migration для перешифрования базы под каноничные ключи (Инвариант №14)
		_, _ = fmt.Fprintln(os.Stderr, "[Lifecycle] Mismatch with server canonical state detected! Launching local Reconcile Migration...")

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
			return fmt.Errorf("local reconcile migration failed: %w", err)
		}

		// Конвейер ReconcileContainer сам атомарно зафиксирует REGISTERED состояние в транзакции SQLite
		return nil
	}

	// 7. ЕСЛИ СВЕРКА ПРОШЛА УСПЕШНО (Мы первый контейнер аккаунта) — СОХРАНЯЕМ СЕТЕВЫЕ ИДЕНТИФИКАТОРЫ
	// Вычисляем DeviceKEK для запечатывания сгенерированного mTLS приватного ключа (Инвариант №9)
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

	// Запечатываем mTLS приватный ключ под локальным DeviceKEK
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

	return s.deviceStore.SaveDeviceState(ctx, updatedState)
}
