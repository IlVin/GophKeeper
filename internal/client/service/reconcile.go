package service

import (
	"context"
	"encoding/json"
	"fmt"

	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/domain/security"

	"golang.org/x/crypto/ssh"
)

// ReconcileContainer приводит локальное состояние контейнера к каноническому серверному виду.
// Вызывается автоматически при регистрации или подключении, если обнаружено несовпадение солей.
func (s *InitService) ReconcileContainer(
	ctx context.Context,
	canonicalSalt []byte,
	canonicalBootstrapEnvJSON []byte,
	serverUserID []byte,
	serverCert []byte,
	serverURL string,
	mtlsSecret security.SecretBytes,
) error {
	// 1. Извлекаем текущее (до-каноническое) состояние из SQLite
	currentState, err := s.deviceStore.ReadDeviceState(ctx)
	if err != nil {
		return fmt.Errorf("failed to read current state for reconcile: %w", err)
	}

	// 2. Восстанавливаем Root of Trust через подключение к ssh-agent
	pubKey, err := ssh.ParsePublicKey(currentState.SshPublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key during reconcile: %w", err)
	}

	fingerprint := sshagent.FingerprintSHA256(pubKey)
	derivationPayload := security.NewDerivationPayload(fingerprint)

	rawSig, err := s.agentClient.SignED25519Raw(fingerprint, derivationPayload.Marshal())
	if err != nil {
		return fmt.Errorf("agent signing during reconcile failed: %w", err)
	}
	derivationSignature := security.SecretBytes(rawSig)
	defer derivationSignature.Destroy()

	// 3. Выводим СТАРЫЙ локальный AccountUnlockKey и DeviceKEK для расшифровки локального кэша
	oldUnlockBytes, err := security.DeriveAccountUnlockKey(derivationSignature, currentState.AccountSalt)
	if err != nil {
		return fmt.Errorf("failed to derive old unlock key: %w", err)
	}
	oldUnlockKey := security.SecretBytes(oldUnlockBytes)
	defer oldUnlockKey.Destroy()

	oldKekBytes, err := security.DeriveDeviceKEK(oldUnlockKey, []byte(currentState.DeviceID))
	if err != nil {
		return fmt.Errorf("failed to derive old device kek: %w", err)
	}
	oldDeviceKEK := security.SecretBytes(oldKekBytes)
	defer oldDeviceKEK.Destroy()

	// Извлекаем и расшифровываем СТАРЫЙ AccountMasterKey (Инвариант №8)
	var oldDeviceEnv security.Envelope
	if err = json.Unmarshal(currentState.DeviceMasterKeyEnvelope, &oldDeviceEnv); err != nil {
		return fmt.Errorf("failed to unmarshal old device envelope: %w", err)
	}

	oldDeviceAAD := security.BuildDeviceMasterKeyAAD(currentState.UserID, currentState.DeviceID)
	oldMasterKeyBytes, err := security.OpenEnvelope(oldDeviceKEK, currentState.DeviceMasterKeyEnvelope, oldDeviceAAD)
	if err != nil {
		return fmt.Errorf("failed to decrypt old master key (tampering detected): %w", err)
	}
	oldAccountMasterKey := security.SecretBytes(oldMasterKeyBytes)
	defer oldAccountMasterKey.Destroy()

	// 4. Выводим НОВЫЙ канонический AccountUnlockKey из присланной сервером соли (Инвариант №1)
	canonicalUnlockBytes, err := security.DeriveAccountUnlockKey(derivationSignature, canonicalSalt)
	if err != nil {
		return fmt.Errorf("failed to derive canonical unlock key: %w", err)
	}
	canonicalUnlockKey := security.SecretBytes(canonicalUnlockBytes)
	defer canonicalUnlockKey.Destroy()

	// Извлекаем НОВЫЙ канонический AccountMasterKey из присланного сервером Bootstrap-конверта
	var canonicalBootstrapEnv security.Envelope
	if err = json.Unmarshal(canonicalBootstrapEnvJSON, &canonicalBootstrapEnv); err != nil {
		return fmt.Errorf("failed to unmarshal canonical bootstrap envelope: %w", err)
	}

	canonicalBootstrapAAD := security.BuildAccountBootstrapAAD(fingerprint)
	canonicalMasterKeyBytes, err := security.OpenEnvelope(canonicalUnlockKey, canonicalBootstrapEnvJSON, canonicalBootstrapAAD)
	if err != nil {
		return fmt.Errorf("failed to open canonical bootstrap envelope (key mismatch): %w", err)
	}
	canonicalAccountMasterKey := security.SecretBytes(canonicalMasterKeyBytes)
	defer canonicalAccountMasterKey.Destroy()

	// 5. ПЕРЕШИФРОВАНИЕ ВСЕХ ПОЛЬЗОВАТЕЛЬСКИХ ЗАПИСЕЙ (Инвариант №14)
	// Для MVP: Запрашиваем интерфейс репозитория секретов через приведение типов (type assertion)
	type recordsFetcher interface {
		// Метод GetAllRecords должен быть реализован в вашем SQLiteSecretStore для пакетной миграции
		GetAllRecords(ctx context.Context) ([]repository.EncryptedRecord, error)
	}

	var localRecords []repository.EncryptedRecord
	if fetcher, ok := s.deviceStore.(recordsFetcher); ok {
		localRecords, err = fetcher.GetAllRecords(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch local records for migration: %w", err)
		}
	}

	migratedRecords := make([]repository.EncryptedRecord, 0, len(localRecords))
	serverUserIDStr := string(serverUserID)

	for _, rec := range localRecords {
		var recEnv security.Envelope
		if err = json.Unmarshal(rec.Envelope, &recEnv); err != nil {
			return fmt.Errorf("failed to unmarshal record %s envelope: %w", rec.ID, err)
		}

		// Вычисляем старый контекст AAD для записи (с использованием старого UserID)
		oldRecInterfaceAAD := security.BuildRecordAAD(currentState.UserID, rec.ID)

		decryptedPayload, err := security.OpenEnvelope(oldAccountMasterKey, rec.Envelope, oldRecInterfaceAAD)
		if err != nil {
			return fmt.Errorf("failed to decrypt record %q during migration: %w", rec.Name, err)
		}

		// Запечатываем данные записи заново под новым каноническим мастер-ключом и новым каноническим UserID
		newRecInterfaceAAD := security.BuildRecordAAD(&serverUserIDStr, rec.ID)
		newRecEnvJSON, err := security.SealEnvelope(
			canonicalAccountMasterKey,
			decryptedPayload,
			newRecInterfaceAAD,
			security.AADSchemaLocalRecord,
		)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt record %q: %w", rec.Name, err)
		}

		// Стираем сырые расшифрованные данные записи из памяти рантайма
		security.SecretBytes(decryptedPayload).Destroy()

		migratedRecords = append(migratedRecords, repository.EncryptedRecord{
			ID:        rec.ID,
			UserID:    &serverUserIDStr,
			Name:      rec.Name,
			Type:      rec.Type,
			Envelope:  newRecEnvJSON,
			CreatedAt: rec.CreatedAt,
			UpdatedAt: rec.UpdatedAt,
		})
	}

	// 6. Выводим новый DeviceKEK на базе канонического ключа разблокировки (Инвариант №2)
	newKekBytes, err := security.DeriveDeviceKEK(canonicalUnlockKey, []byte(currentState.DeviceID))
	if err != nil {
		return fmt.Errorf("failed to derive new device kek: %w", err)
	}
	newDeviceKEK := security.SecretBytes(newKekBytes)
	defer newDeviceKEK.Destroy()

	// Переупаковываем локальный DeviceMasterKeyEnvelope под новым DeviceKEK и новым каноническим AAD
	newDeviceAAD := security.BuildDeviceMasterKeyAAD(&serverUserIDStr, currentState.DeviceID)
	newDeviceEnvJSON, err := security.SealEnvelope(
		newDeviceKEK,
		canonicalAccountMasterKey,
		newDeviceAAD,
		security.AADSchemaDeviceMasterKey,
	)
	if err != nil {
		return fmt.Errorf("failed to seal new device master key envelope: %w", err)
	}

	// 7. МИГРАЦИЯ mTLS PRIV KEY (Если он присутствует локально)
	var newMtlsJSON []byte
	if currentState.EncryptedMtlsPrivateKey != nil && len(*currentState.EncryptedMtlsPrivateKey) > 0 {
		var oldMtlsEnv security.Envelope
		_ = json.Unmarshal(*currentState.EncryptedMtlsPrivateKey, &oldMtlsEnv)

		oldMtlsAAD := security.BuildDeviceMasterKeyAAD(currentState.UserID, currentState.DeviceID)
		rawMtlsPriv, err := security.OpenEnvelope(oldDeviceKEK, *currentState.EncryptedMtlsPrivateKey, oldMtlsAAD)
		if err != nil {
			return fmt.Errorf("failed to decrypt mTLS private key during reconcile: %w", err)
		}
		mtlsSecret := security.SecretBytes(rawMtlsPriv)
		defer mtlsSecret.Destroy()

		newMtlsAAD := security.BuildDeviceMasterKeyAAD(&serverUserIDStr, currentState.DeviceID)
		newMtlsJSON, err = security.SealEnvelope(newDeviceKEK, mtlsSecret, newMtlsAAD, security.AADSchemaDeviceMasterKey)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt mTLS private key: %w", err)
		}
	}

	// =========================================================================
	// 7. ЗАПЕЧАТЫВАНИЕ mTLS PRIV KEY, ПОЛУЧЕННОГО ИЗ ФАЗЫ РЕГИСТРАЦИИ (Инвариант №9)
	// =========================================================================
	newMtlsAAD := security.BuildDeviceMasterKeyAAD(&serverUserIDStr, currentState.DeviceID)
	newMtlsJSON, err = security.SealEnvelope(newDeviceKEK, mtlsSecret, newMtlsAAD, security.AADSchemaDeviceMasterKey)
	if err != nil {
		return fmt.Errorf("failed to seal fresh mTLS private key under canonical device kek: %w", err)
	}

	// 8. СБОРКА ФИНАЛЬНОГО КАНОНИЧЕСКОГО СОСТОЯНИЯ УСТРОЙСТВА
	serverURLStr := serverURL

	updatedState := &repository.LocalDeviceState{
		ServerURL:                &serverURLStr,
		UserID:                   &serverUserIDStr,
		DeviceID:                 currentState.DeviceID,
		SshPublicKey:             currentState.SshPublicKey,
		AccountSalt:              canonicalSalt,
		DeviceMasterKeyEnvelope:  newDeviceEnvJSON,
		AccountBootstrapEnvelope: canonicalBootstrapEnvJSON,
		EncryptedMtlsPrivateKey:  &newMtlsJSON,
		ClientCertificate:        &serverCert,
		CreatedAt:                currentState.CreatedAt,
	}

	// 9. ФИКСАЦИЯ ИЗМЕНЕНИЙ В ОДНОЙ ТРАНЗАКЦИИ (Инвариант №15)
	type transactedReconciler interface {
		// Метод ExecuteReconcileTransaction должен атомарно обновить device_state и подменить таблицу records
		ExecuteReconcileTransaction(ctx context.Context, state *repository.LocalDeviceState, records []repository.EncryptedRecord) error
	}

	if dbTx, ok := s.deviceStore.(transactedReconciler); ok {
		return dbTx.ExecuteReconcileTransaction(ctx, updatedState, migratedRecords)
	}

	return fmt.Errorf("device store does not implement atomic transaction reconciliation interface")
}
