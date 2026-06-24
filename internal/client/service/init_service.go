// Package service содержит компоненты бизнес-логики клиентского приложения GophKeeper,
// оркеструющие криптографические конвейеры, вызовы деривации и сетевую синхронизацию.
package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"time"

	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/domain/security"

	"github.com/google/uuid"
)

// InitService координирует бизнес-логику создания и разворачивания локального
// криптографического окружения и формирования корневых защищенных конвертов.
type InitService struct {
	deviceStore repository.DeviceStore
	agentClient *sshagent.Client
}

// NewInitService конструирует новый экземпляр InitService.
func NewInitService(store repository.DeviceStore, agent *sshagent.Client) *InitService {
	return &InitService{
		deviceStore: store,
		agentClient: agent,
	}
}

// ExecuteLocalInit выполняет сквозной криптографический конвейер локальной инициализации сейфа.
//
// Функция верифицирует программную природу SSH-ключа, генерирует криптографическую соль,
// выводит AccountUnlockKey и DeviceKEK, а затем атомарно формирует и сохраняет в СУБД SQLite
// базовые конверты защиты AccountMasterKey (Инварианты №1, №2, №3, №7, №8, №9).
func (s *InitService) ExecuteLocalInit(ctx context.Context, serverURL string, fingerprint string, pubKeyBytes []byte) error {
	slog.Info("Starting cryptographic local core initialization pipeline")

	// 1. Проверяем ключ в агенте, используя динамический nonce для защиты от replay-атак
	testNonce := []byte(fmt.Sprintf("gophkeeper-init-nonce-%s-%d", uuid.New().String(), time.Now().UnixNano()))
	if err := s.agentClient.SelfTestDeterministicED25519(fingerprint, testNonce); err != nil {
		slog.Error("SSH key self-test validation failed: randomized hardware token detected", "fingerprint", fingerprint, "error", err)
		return fmt.Errorf("ssh-agent key self-test failed: %w", err)
	}

	// 2. Сборка DerivationPayload и получение DerivationSignature через сокет агента
	slog.Debug("Requesting root derivation signature block from ssh-agent")
	payload := security.NewDerivationPayload(fingerprint)
	rawSig, err := s.agentClient.SignED25519Raw(fingerprint, payload.Marshal())
	if err != nil {
		return fmt.Errorf("failed to sign derivation payload: %w", err)
	}
	derivationSignature := security.SecretBytes(rawSig)
	defer derivationSignature.Destroy()

	// 3. Гарантированная генерация стабильной AccountSalt (32 байта) (Инвариант №1)
	accountSalt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, accountSalt); err != nil {
		return fmt.Errorf("generate account salt: %w", err)
	}

	// ГАРАНТИЯ ИБ (RAM Hygiene): Обеспечиваем принудительную зачистку соли при сбоях
	cleanUpSaltNeeded := true
	defer func() {
		if cleanUpSaltNeeded {
			for i := range accountSalt {
				accountSalt[i] = 0
			}
			slog.Debug("Emergency erasure of account salt from heap completed due to failure")
		}
	}()

	// 4. Вывод AccountUnlockKey из подписи и соли
	slog.Debug("Deriving AccountUnlockKey material via crypto core")
	unlockKey, err := security.DeriveAccountUnlockKey(derivationSignature, accountSalt)
	if err != nil {
		return fmt.Errorf("derive account unlock key: %w", err)
	}
	defer unlockKey.Destroy()

	// 5. Генерация случайного AccountMasterKey (32 байта) (Инвариант №7)
	slog.Debug("Generating random highly-entropic AccountMasterKey")
	masterKey, err := security.GenerateRandomKey(32)
	if err != nil {
		return fmt.Errorf("generate master key: %w", err)
	}
	defer masterKey.Destroy()

	// 6. Доменный сдвиг: Жестко связываем сетевую идентичность с криптографическим фингерпринтом
	devID := uuid.New().String()
	userIDStr := fingerprint

	// 7. Вывод DeviceKEK для локальной привязки контейнера (Инвариант №2)
	slog.Debug("Deriving DeviceKEK symmetric key linked to current container UUID")
	deviceKEK, err := security.DeriveDeviceKEK(unlockKey, []byte(devID))
	if err != nil {
		return fmt.Errorf("derive device kek: %w", err)
	}
	defer deviceKEK.Destroy()

	// 8. Запечатывание конвертов XChaCha20-Poly1305 (Инварианты №8, №9)
	slog.Debug("Sealing secure cloud bootstrap envelope under AccountUnlockKey")
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

	slog.Debug("Sealing secure local master key envelope under DeviceKEK")
	deviceAAD := security.BuildDeviceMasterKeyAAD(&userIDStr, devID)
	deviceMasterKeyEnvelopeJSON, err := security.SealEnvelope(
		deviceKEK,
		masterKey,
		deviceAAD,
		security.AADSchemaDeviceMasterKey,
	)
	if err != nil {
		return fmt.Errorf("failed to seal device master key envelope: %w", err)
	}

	// 9. Сборка структуры состояния синглтон-устройства
	state := &repository.LocalDeviceState{
		ServerURL:                nil,        // Заполняется позже на этапе register
		UserID:                   &userIDStr, // Привязывается монолитно намертво при init
		DeviceID:                 devID,
		SshPublicKey:             pubKeyBytes,
		AccountSalt:              accountSalt,
		AccountBootstrapEnvelope: bootstrapEnvelopeJSON,
		DeviceMasterKeyEnvelope:  deviceMasterKeyEnvelopeJSON,
		EncryptedMtlsPrivateKey:  nil, // Генерируется на этапе register
		ClientCertificate:        nil,
		CreatedAt:                time.Now().UTC().Format(time.RFC3339Nano),
	}

	// 10. Атомарное персистентное сохранение состояния в СУБД SQLite
	slog.Debug("Persisting initial validated device state singleton structure to SQLite")
	if err := s.deviceStore.SaveDeviceState(ctx, state); err != nil {
		return fmt.Errorf("save initial device state: %w", err)
	}

	// Снимаем флаг экстренной очистки, так как соль успешно легитимизирована в СУБД
	cleanUpSaltNeeded = false

	slog.Info("Cryptographic local core initialisation pipeline completed successfully")
	return nil
}
