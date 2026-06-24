// Package service содержит компоненты бизнес-логики клиентского приложения GophKeeper,
// оркеструющие криптографические конвейеры, вызовы деривации и сетевую синхронизацию.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/domain/security"

	"golang.org/x/crypto/ssh"
)

// SecretService координирует операции шифрования, дешифрования, удаления
// и листинга пользовательских секретных записей (паролей, файлов, карт).
type SecretService struct {
	secretStore repository.SecretStore
	deviceStore repository.DeviceStore
	agentClient *sshagent.Client
}

// NewSecretService конструирует новый экземпляр координатора крипто-сервиса секретов.
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

// CreateSecret запечатывает полезную нагрузку под AccountMasterKey и атомарно сохраняет в SQLite СУБД.
func (s *SecretService) CreateSecret(ctx context.Context, name, secretType string, plaintextPayload []byte) error {
	if len(plaintextPayload) == 0 {
		return errors.New("secret payload cannot be empty")
	}

	slog.Info("Initiating local record encryption and persistence pipeline", "name", name, "type", secretType)

	// 1. Извлекаем текущее состояние устройства из БД
	state, err := s.deviceStore.ReadDeviceState(ctx)
	if err != nil {
		return fmt.Errorf("failed to read device state: %w", err)
	}

	// ЗАЩИТНЫЙ ИБ-БАРЬЕР: Предотвращает панику, если база пуста
	if state == nil {
		slog.Warn("Record creation rejected: local environment is not initialized")
		return errors.New("environment is not initialized: please run 'gophkeeper init' first")
	}

	// 2. Восстанавливаем AccountMasterKey из RAM через цепочку деривации (Инвариант №8)
	masterKey, err := s.unlockMasterKey(ctx, state)
	if err != nil {
		return fmt.Errorf("failed to unlock vault master key: %w", err)
	}
	defer masterKey.Destroy() // Гарантированное выжигание ключа из RAM по выходу

	// 3. Вычисляем детерминированный UUID v5 для новой записи на базе её имени
	recordID := security.DeriveRecordID(name)

	// 4. Сборка контекста защиты AAD для привязки записи к текущему пользователю (Инвариант №6)
	recordAAD := security.BuildRecordAAD(state.UserID, recordID)

	// 5. Симметричное шифрование XChaCha20-Poly1305
	slog.Debug("Sealing plaintext record payload into secure Poly1305 crypt-envelope")
	envelopeJSON, err := security.SealEnvelope(
		masterKey,
		plaintextPayload,
		recordAAD,
		security.AADSchemaLocalRecord,
	)
	if err != nil {
		slog.Error("XChaCha20 encryption pipeline failed", "error", err)
		return fmt.Errorf("failed to encrypt secret payload: %w", err)
	}

	// 6. Формируем структуру для записи в репозиторий SQLite
	now := time.Now().UTC()
	record := &repository.EncryptedRecord{
		ID:        recordID,
		UserID:    state.UserID,
		Name:      name,
		Type:      secretType,
		Envelope:  envelopeJSON,
		CreatedAt: now,
		UpdatedAt: now,
		IsDeleted: 0, // Явно указываем, что запись живая
	}

	slog.Debug("Persisting encrypted record block to SQLite records table", "id", recordID)
	if err := s.secretStore.Save(ctx, record); err != nil {
		return fmt.Errorf("failed to persist record to database: %w", err)
	}

	slog.Info("Record successfully encrypted and committed to local vault")
	return nil
}

// UnsealSecret извлекает зашифрованный конверт из СУБД, верифицирует его целостность и расшифровывает.
func (s *SecretService) UnsealSecret(ctx context.Context, idOrName string, isFindByID bool) (string, []byte, error) {
	slog.Info("Initiating secret record fetching and decryption pipeline")

	state, err := s.deviceStore.ReadDeviceState(ctx)
	if err != nil {
		return "", nil, err
	}
	if state == nil {
		return "", nil, errors.New("environment is not initialized: please run 'gophkeeper init' first")
	}

	// 1. Поиск записи в репозитории СУБД
	var record *repository.EncryptedRecord
	if isFindByID {
		slog.Debug("Executing database lookup by record UUID", "id", idOrName)
		record, err = s.secretStore.GetByID(ctx, idOrName)
	} else {
		slog.Debug("Executing database lookup by record human-readable name", "name", idOrName)
		record, err = s.secretStore.GetByName(ctx, idOrName)
	}
	if err != nil {
		return "", nil, err
	}
	if record == nil {
		slog.Warn("Record fetching rejected: identifier not found in sqlite target context")
		return "", nil, errors.New("secret record not found")
	}

	// 2. Криптографическое вскрытие общего мастер-ключа приложения
	masterKey, err := s.unlockMasterKey(ctx, state)
	if err != nil {
		return "", nil, err
	}
	defer masterKey.Destroy()

	// 3. Вычисление контекста защиты AAD для верификации аутентификационного тега Poly1305
	recordAAD := security.BuildRecordAAD(state.UserID, record.ID)

	// 4. Вскрытие конверта XChaCha20-Poly1305 с проверкой целостности структуры
	slog.Debug("Opening secret envelope via AccountMasterKey", "record_id", record.ID)
	plaintext, err := security.OpenEnvelope(masterKey, record.Envelope, recordAAD)
	if err != nil {
		slog.Error("Poly1305 tag verification failed: record envelope corrupted or key mismatch", "record_id", record.ID)
		return "", nil, fmt.Errorf("failed to open secret envelope (tampering or key mismatch): %w", err)
	}

	slog.Info("Secret record successfully decrypted and verified")
	return record.Name, plaintext, nil
}

// ListSecrets возвращает плоский список легковесных метаданных для CLI-отображения.
func (s *SecretService) ListSecrets(ctx context.Context) ([]repository.RecordMetadata, error) {
	return s.secretStore.List(ctx)
}

// DeleteSecret безвозвратно удаляет строку записи из базы данных по её UUID.
func (s *SecretService) DeleteSecret(ctx context.Context, id string) error {
	return s.secretStore.Delete(ctx, id)
}

// --- Внутренние инфраструктурные крипто-хелперы сервиса ---

// unlockMasterKey восстанавливает AccountMasterKey из RAM через пошаговую цепочку деривации (Инвариант №8)
func (s *SecretService) unlockMasterKey(ctx context.Context, state *repository.LocalDeviceState) (security.SecretBytes, error) {
	slog.Debug("Executing step-by-step master key derivation loop from ssh-agent root of trust")

	pubKey, err := ssh.ParsePublicKey(state.SshPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stored public key structure: %w", err)
	}
	fingerprint := sshagent.FingerprintSHA256(pubKey)

	// 1. Сборка DerivationPayload и вызов подписи в ssh-agent сокете
	derivationPayload := security.NewDerivationPayload(fingerprint)
	rawSig, err := s.agentClient.SignED25519Raw(fingerprint, derivationPayload.Marshal())
	if err != nil {
		return nil, fmt.Errorf("ssh-agent signing rejected: %w", err)
	}
	derivationSignature := security.SecretBytes(rawSig)
	defer derivationSignature.Destroy()

	// 2. Деривация AccountUnlockKey на базе подписи и соли
	unlockBytes, err := security.DeriveAccountUnlockKey(derivationSignature, state.AccountSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive account unlock key: %w", err)
	}
	unlockKey := security.SecretBytes(unlockBytes)
	defer unlockKey.Destroy()

	// 3. Деривация DeviceKEK на базе DeviceID контейнера (Инвариант №2)
	deviceKekBytes, err := security.DeriveDeviceKEK(unlockKey, []byte(state.DeviceID))
	if err != nil {
		return nil, fmt.Errorf("failed to derive symmetric device kek: %w", err)
	}
	deviceKEK := security.SecretBytes(deviceKekBytes)
	defer deviceKEK.Destroy()

	// 4. Открываем DeviceMasterKeyEnvelope с полной проверкой целостности контекста AAD
	var deviceEnv security.Envelope
	if err := json.Unmarshal(state.DeviceMasterKeyEnvelope, &deviceEnv); err != nil {
		return nil, fmt.Errorf("failed to unmarshal device master envelope layout: %w", err)
	}
	deviceAAD := security.BuildDeviceMasterKeyAAD(state.UserID, state.DeviceID)

	slog.Debug("Opening local device envelope via derived DeviceKEK")
	masterKeyBytes, err := security.OpenEnvelope(deviceKEK, state.DeviceMasterKeyEnvelope, deviceAAD)
	if err != nil {
		slog.Error("Device master key envelope verification failed: local state tampering detected")
		return nil, fmt.Errorf("master key envelope corruption: %w", err)
	}

	return security.SecretBytes(masterKeyBytes), nil
}

// VerifyOwner верифицирует, что в текущем ssh-agent загружен именно тот корень доверия, который привязан к сейфу.
func (s *SecretService) VerifyOwner(ctx context.Context) error {
	state, err := s.deviceStore.ReadDeviceState(ctx)
	if err != nil {
		return fmt.Errorf("failed to read device state: %w", err)
	}
	if state == nil {
		return errors.New("access denied: local environment is not initialized")
	}

	// Запуск деривации. Если ключ чужой, метод выкинет ИБ-ошибку Poly1305 authentication failed.
	masterKey, err := s.unlockMasterKey(ctx, state)
	if err != nil {
		return fmt.Errorf("access denied: signature verification failed or root SSH key missing from agent: %w", err)
	}

	// Мгновенно уничтожаем мастер-ключ из памяти, так как факт успеха деривации подтвердил владение
	masterKey.Destroy()
	return nil
}
