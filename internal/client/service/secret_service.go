package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/domain/security"

	"golang.org/x/crypto/ssh"
)

type SecretService struct {
	secretStore repository.SecretStore
	deviceStore repository.DeviceStore // Нужен для чтения DeviceMasterKeyEnvelope
	agentClient *sshagent.Client
}

func NewSecretService(
	ss repository.SecretStore,
	ds repository.DeviceStore,
	agent *sshagent.Client,
) *SecretService {
	return &SecretService{
		secretStore: ss,
		deviceStore: ds,
		agentClient: agent,
	}
}

// CreateSecret запечатывает сырые данные секрета под AccountMasterKey и сохраняет в SQLite
func (s *SecretService) CreateSecret(ctx context.Context, name, secretType string, plaintextPayload []byte) error {
	if len(plaintextPayload) == 0 {
		return errors.New("secret payload cannot be empty")
	}

	// 1. Извлекаем текущее состояние устройства из БД для получения метаданных ключа
	state, err := s.deviceStore.ReadDeviceState(ctx)
	if err != nil {
		return fmt.Errorf("failed to read device state: %w", err)
	}

	// 2. Восстанавливаем AccountMasterKey из RAM через цепочку деривации (Инвариант №8)
	masterKey, err := s.unlockMasterKey(ctx, state)
	if err != nil {
		return fmt.Errorf("failed to unlock vault master key: %w", err)
	}
	defer masterKey.Destroy() // Гарантированная очистка памяти по выходу

	// 3. Генерируем UUID для новой записи
	recordID := security.DeriveRecordID(name)

	// 4. Сборка контекста защиты AAD для записи (Инвариант №6)
	recordAAD := security.BuildRecordAAD(state.UserID, recordID)

	// 5. Симметричное шифрование XChaCha20-Poly1305
	envelopeJSON, err := security.SealEnvelope(
		masterKey,
		plaintextPayload,
		recordAAD,
		security.AADSchemaLocalRecord,
	)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret payload: %w", err)
	}

	// 6. Формируем структуру для записи в репозиторий
	now := time.Now().UTC()
	record := &repository.EncryptedRecord{
		ID:        recordID,
		UserID:    state.UserID,
		Name:      name,
		Type:      secretType,
		Envelope:  envelopeJSON,
		CreatedAt: now,
		UpdatedAt: now,
	}

	return s.secretStore.Save(ctx, record)
}

// UnsealSecret извлекает зашифрованный конверт из БД, проверяет целостность и расшифровывает его
func (s *SecretService) UnsealSecret(ctx context.Context, idOrName string, isFindByID bool) (string, []byte, error) {
	state, err := s.deviceStore.ReadDeviceState(ctx)
	if err != nil {
		return "", nil, err
	}

	// 1. Поиск записи в БД
	var record *repository.EncryptedRecord
	if isFindByID {
		record, err = s.secretStore.GetByID(ctx, idOrName)
	} else {
		record, err = s.secretStore.GetByName(ctx, idOrName)
	}
	if err != nil {
		return "", nil, err
	}
	if record == nil {
		return "", nil, errors.New("secret record not found")
	}

	// 2. Восстановление мастер-ключей
	masterKey, err := s.unlockMasterKey(ctx, state)
	if err != nil {
		return "", nil, err
	}
	defer masterKey.Destroy()

	// 3. Вычисление контекста защиты AAD для верификации целостности тега Poly1305
	recordAAD := security.BuildRecordAAD(state.UserID, record.ID)

	// 4. Расширение конверта
	plaintext, err := security.OpenEnvelope(masterKey, record.Envelope, recordAAD)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open secret envelope (tampering or key mismatch): %w", err)
	}

	return record.Name, plaintext, nil
}

// ListSecrets возвращает плоский список доступных метаданных
func (s *SecretService) ListSecrets(ctx context.Context) ([]repository.RecordMetadata, error) {
	return s.secretStore.List(ctx)
}

// DeleteSecret удаляет запись из базы данных по её UUID
func (s *SecretService) DeleteSecret(ctx context.Context, id string) error {
	return s.secretStore.Delete(ctx, id)
}

// --- Внутренние криптографические хелперы сервиса ---

func (s *SecretService) unlockMasterKey(ctx context.Context, state *repository.LocalDeviceState) (security.SecretBytes, error) {
	// Парсим публичный ключ для получения фингерпринта
	pubKey, err := ssh.ParsePublicKey(state.SshPublicKey)
	if err != nil {
		return nil, err
	}
	fingerprint := sshagent.FingerprintSHA256(pubKey)

	// 1. Сборка DerivationPayload и вызов подписи в ssh-agent
	derivationPayload := security.NewDerivationPayload(fingerprint)
	rawSig, err := s.agentClient.SignED25519Raw(fingerprint, derivationPayload.Marshal())
	if err != nil {
		return nil, fmt.Errorf("ssh-agent signing rejected: %w", err)
	}
	derivationSignature := security.SecretBytes(rawSig)
	defer derivationSignature.Destroy()

	unlockKey, err := security.DeriveAccountUnlockKey(derivationSignature, state.AccountSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account unlock key: %w", err)
	}
	defer unlockKey.Destroy()

	// 3. Выводим DeviceKEK (Инвариант №2)
	deviceKEK, err := security.DeriveDeviceKEK(unlockKey, []byte(state.DeviceID))
	if err != nil {
		return nil, err
	}
	defer deviceKEK.Destroy()

	// 4. Открываем DeviceMasterKeyEnvelope с проверкой AAD
	var deviceEnv security.Envelope
	if err := json.Unmarshal(state.DeviceMasterKeyEnvelope, &deviceEnv); err != nil {
		return nil, err
	}
	deviceAAD := security.BuildDeviceMasterKeyAAD(state.UserID, state.DeviceID)

	masterKeyBytes, err := security.OpenEnvelope(deviceKEK, state.DeviceMasterKeyEnvelope, deviceAAD)
	if err != nil {
		return nil, fmt.Errorf("master key envelope corruption: %w", err)
	}

	return security.SecretBytes(masterKeyBytes), nil
}

// VerifyOwner проверяет, что в текущем ssh-agent загружен именно тот ключ,
// который является корнем доверия для данного контейнера (Инвариант Proof of Possession)
func (s *SecretService) VerifyOwner(ctx context.Context) error {
	state, err := s.deviceStore.ReadDeviceState(ctx)
	if err != nil {
		return fmt.Errorf("failed to read device state: %w", err)
	}

	// Вызываем наш существующий криптографический конвейер деривации.
	// Если ключ в агенте чужой или отсутствует, метод выкинет ошибку Poly1305 authentication failed.
	masterKey, err := s.unlockMasterKey(ctx, state)
	if err != nil {
		return fmt.Errorf("access denied: signature verification failed or root SSH key missing from agent: %w", err)
	}

	// Мгновенно уничтожаем мастер-ключ из памяти, так как для проверки нам был нужен только факт успеха
	masterKey.Destroy()
	return nil
}
