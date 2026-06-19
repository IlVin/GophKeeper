package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/domain/security"

	"github.com/google/uuid"
)

type InitService struct {
	deviceStore repository.DeviceStore
	agentClient *sshagent.Client
}

func NewInitService(store repository.DeviceStore, agent *sshagent.Client) *InitService {
	return &InitService{
		deviceStore: store,
		agentClient: agent,
	}
}

func (s *InitService) ExecuteLocalInit(ctx context.Context, serverURL string, fingerprint string, pubKeyBytes []byte) error {
	// 1. Проверяем ключ в агенте и прогоняем детерминированный тест (Инвариант №3)
	if err := s.agentClient.SelfTestDeterministicED25519(fingerprint, []byte("test")); err != nil {
		return fmt.Errorf("ssh-agent key self-test failed: %w", err)
	}

	// 2. Сборка DerivationPayload и получение DerivationSignature
	payload := security.NewDerivationPayload(fingerprint)
	rawSig, err := s.agentClient.SignED25519Raw(fingerprint, payload.Marshal())
	if err != nil {
		return fmt.Errorf("failed to sign derivation payload: %w", err)
	}
	derivationSignature := security.SecretBytes(rawSig)
	defer derivationSignature.Destroy()

	// 3. Генерация AccountSalt (32 байта)
	accountSalt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, accountSalt); err != nil {
		return fmt.Errorf("generate account salt: %w", err)
	}

	// 4. Вывод AccountUnlockKey
	unlockKey, err := security.DeriveAccountUnlockKey(derivationSignature, accountSalt)
	if err != nil {
		return fmt.Errorf("derive account unlock key: %w", err)
	}
	defer unlockKey.Destroy()

	// 5. Генерация случайного AccountMasterKey (32 байта)
	masterKey, err := security.GenerateRandomKey(32)
	if err != nil {
		return fmt.Errorf("generate master key: %w", err)
	}
	defer masterKey.Destroy()

	// 6. Генерация DeviceID (Public UUID)
	devID := uuid.New().String()

	// 7. Вывод DeviceKEK
	deviceKEK, err := security.DeriveDeviceKEK(unlockKey, []byte(devID))
	if err != nil {
		return fmt.Errorf("derive device kek: %w", err)
	}
	defer deviceKEK.Destroy()

	// 8. Запечатывание конвертов
	// Инварианты №8, №9: Разные слои защиты для Bootstrap и Device эндпоинтов

	// Контекст ААD для облачного Bootstrap-конверта на базе фингерпринта
	bootstrapAAD := security.BuildAccountBootstrapAAD(fingerprint)
	bootstrapEnvelopeJSON, err := security.SealEnvelope(
		unlockKey,
		masterKey,
		bootstrapAAD,
		security.AADSchemaAccountBootstrap,
	)
	if err != nil {
		return fmt.Errorf("failed to seal account bootstrap envelope: %w", err)
	}

	// Контекст AAD для локального привязанного конверта на базе DeviceID (userID пока nil)
	deviceAAD := security.BuildDeviceMasterKeyAAD(nil, devID)
	deviceMasterKeyEnvelopeJSON, err := security.SealEnvelope(
		deviceKEK,
		masterKey,
		deviceAAD,
		security.AADSchemaDeviceMasterKey,
	)
	if err != nil {
		return fmt.Errorf("failed to seal device master key envelope: %w", err)
	}

	// 9. Сборка структуры состояния устройства
	state := &repository.LocalDeviceState{
		ServerURL:                nil,
		UserID:                   nil,
		DeviceID:                 devID,
		SshPublicKey:             pubKeyBytes,
		AccountSalt:              accountSalt,
		AccountBootstrapEnvelope: bootstrapEnvelopeJSON,
		DeviceMasterKeyEnvelope:  deviceMasterKeyEnvelopeJSON,
		EncryptedMtlsPrivateKey:  nil,
		ClientCertificate:        nil,
		CreatedAt:                time.Now().UTC().Format(time.RFC3339),
	}

	// 10. Атомарное сохранение в SQLite
	if err := s.deviceStore.SaveDeviceState(ctx, state); err != nil {
		return fmt.Errorf("save initial device state: %w", err)
	}

	return nil
}
