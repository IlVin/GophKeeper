// Package service содержит компоненты бизнес-логики клиентского приложения GophKeeper,
// оркеструющие криптографические конвейеры, вызовы деривации и сетевую синхронизацию.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/client/repository"
	"gophkeeper/internal/domain/security"

	"golang.org/x/crypto/ssh"
)

// ReconcileContainer атомарно приводит локальную структуру контейнера к каноническому серверному виду.
//
// Функция выполняет полную деэнкрипцию локального кэша старыми ключами, выводит новые KEK
// на базе присланной сервером соли и каскадно перешифровывает все records под новый контекст AAD,
// защищая распределенную систему от рассинхронизации (Инварианты №1, №2, №8, №9, №14, №15).
func (s *InitService) ReconcileContainer(
	ctx context.Context,
	canonicalSalt []byte,
	canonicalBootstrapEnvJSON []byte,
	serverUserID []byte,
	serverCert []byte,
	serverURL string,
	freshMtlsPrivateKey security.SecretBytes, // Конфиденциальный mTLS ключ из фазы register
) error {
	slog.Info("Initiating global local container cryptographic reconciliation pipeline")

	// 1. Извлекаем текущую конфигурацию синглтона из SQLite через легитимный метод интерфейса
	currentState, err := s.deviceStore.ReadDeviceState(ctx)
	if err != nil {
		slog.Error("Reconcile aborted: failed to read device state baseline", "error", err)
		return fmt.Errorf("read current state for reconcile: %w", err)
	}

	// ДОБАВЛЕН ЗАЩИТНЫЙ ИБ-БАРЬЕР: Предотвращает панику, если база вернула пустой указатель
	if currentState == nil {
		slog.Warn("Reconcile rejected: local container is completely uninitialized")
		return errors.New("read current state for reconcile: local container state is missing, please run init first")
	}

	// 2. Восстанавливаем Root of Trust через сокет ssh-agent
	pubKey, err := ssh.ParsePublicKey(currentState.SshPublicKey)
	if err != nil {
		return fmt.Errorf("parse public key during reconcile: %w", err)
	}
	fingerprint := sshagent.FingerprintSHA256(pubKey)

	slog.Debug("Requesting authentication signature from ssh-agent for reconcile token verification")
	derivationPayload := security.NewDerivationPayload(fingerprint)
	rawSig, err := s.agentClient.SignED25519Raw(fingerprint, derivationPayload.Marshal())
	if err != nil {
		return fmt.Errorf("agent signing during reconcile failed: %w", err)
	}
	derivationSignature := security.SecretBytes(rawSig)
	defer derivationSignature.Destroy()

	// 3. Выводим СТАРЫЙ локальный AccountUnlockKey и DeviceKEK для вскрытия кэша
	oldUnlockBytes, err := security.DeriveAccountUnlockKey(derivationSignature, currentState.AccountSalt)
	if err != nil {
		return fmt.Errorf("derive old unlock key: %w", err)
	}
	oldUnlockKey := security.SecretBytes(oldUnlockBytes)
	defer oldUnlockKey.Destroy()

	oldKekBytes, err := security.DeriveDeviceKEK(oldUnlockKey, []byte(currentState.DeviceID))
	if err != nil {
		return fmt.Errorf("derive old device kek: %w", err)
	}
	oldDeviceKEK := security.SecretBytes(oldKekBytes)
	defer oldDeviceKEK.Destroy()

	// Извлекаем и расшифровываем СТАРЫЙ AccountMasterKey для вскрытия записей
	slog.Debug("Opening old local master key envelope via obsolete DeviceKEK")
	oldDeviceAAD := security.BuildDeviceMasterKeyAAD(currentState.UserID, currentState.DeviceID)
	oldMasterKeyBytes, err := security.OpenEnvelope(oldDeviceKEK, currentState.DeviceMasterKeyEnvelope, oldDeviceAAD)
	if err != nil {
		slog.Error("Reconcile structural block violation: local container tampering detected", "error", err)
		return fmt.Errorf("open old master key envelope: %w", err)
	}
	oldAccountMasterKey := security.SecretBytes(oldMasterKeyBytes)
	defer oldAccountMasterKey.Destroy()

	// 4. Выводим НОВЫЙ канонический AccountUnlockKey из присланной сервером соли
	slog.Debug("Deriving canonical AccountUnlockKey via fresh server salt token")
	canonicalUnlockBytes, err := security.DeriveAccountUnlockKey(derivationSignature, canonicalSalt)
	if err != nil {
		return fmt.Errorf("derive canonical unlock key: %w", err)
	}
	canonicalUnlockKey := security.SecretBytes(canonicalUnlockBytes)
	defer canonicalUnlockKey.Destroy()

	// Извлекаем НОВЫЙ канонический AccountMasterKey из присланного сервером Bootstrap-конверта
	slog.Debug("Opening canonical bootstrap cloud envelope via fresh AccountUnlockKey")
	canonicalBootstrapAAD := security.BuildAccountBootstrapAAD(fingerprint)
	canonicalMasterKeyBytes, err := security.OpenEnvelope(canonicalUnlockKey, canonicalBootstrapEnvJSON, canonicalBootstrapAAD)
	if err != nil {
		slog.Error("Reconcile master key sync failed: server envelope key mismatch", "error", err)
		return fmt.Errorf("open canonical bootstrap envelope: %w", err)
	}
	canonicalAccountMasterKey := security.SecretBytes(canonicalMasterKeyBytes)
	defer canonicalAccountMasterKey.Destroy()

	// 5. ПЕРЕШИФРОВАНИЕ ВСЕХ ПОЛЬЗОВАТЕЛЬСКИХ ЗАПИСЕЙ (Инвариант №14)
	slog.Debug("Fetching all local encrypted records for cascade re-encryption step")
	localRecords, err := s.deviceStore.GetAllRecords(ctx)
	if err != nil {
		return fmt.Errorf("fetch local records for migration: %w", err)
	}

	migratedRecords := make([]repository.EncryptedRecord, 0, len(localRecords))
	serverUserIDStr := string(serverUserID)

	slog.Info("Iterating over local cache, executing XChaCha20-Poly1305 re-encryption loop", "count", len(localRecords))
	for _, rec := range localRecords {
		// Вычисляем старый контекст AAD для расшифровки записи
		oldRecInterfaceAAD := security.BuildRecordAAD(currentState.UserID, rec.ID)
		decryptedPayload, err := security.OpenEnvelope(oldAccountMasterKey, rec.Envelope, oldRecInterfaceAAD)
		if err != nil {
			return fmt.Errorf("failed to decrypt record %q during migration cascade: %w", rec.Name, err)
		}

		// Запечатываем данные записи заново под НОВЫМ каноническим мастер-ключом и НОВЫМ каноническим UserID
		newRecInterfaceAAD := security.BuildRecordAAD(&serverUserIDStr, rec.ID)
		newRecEnvJSON, err := security.SealEnvelope(
			canonicalAccountMasterKey,
			decryptedPayload,
			newRecInterfaceAAD,
			security.AADSchemaLocalRecord,
		)

		// RAM Hygiene: Стираем сырые расшифрованные данные записи мгновенно по выходу из конвейера
		security.SecretBytes(decryptedPayload).Destroy()

		if err != nil {
			return fmt.Errorf("failed to re-encrypt record %q under canonical components: %w", rec.Name, err)
		}

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

	// 6. Выводим новый DeviceKEK на базе канонического ключа разблокировки
	slog.Debug("Deriving canonical DeviceKEK linked to current container UUID")
	newKekBytes, err := security.DeriveDeviceKEK(canonicalUnlockKey, []byte(currentState.DeviceID))
	if err != nil {
		return fmt.Errorf("derive new device kek: %w", err)
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
		return fmt.Errorf("seal new device master key envelope: %w", err)
	}

	// 7. МИГРАЦИЯ mTLS PRIV KEY (Исправлен критический баг дублирования и затирания)
	var newMtlsJSON []byte
	newMtlsAAD := security.BuildDeviceMasterKeyAAD(&serverUserIDStr, currentState.DeviceID)

	if freshMtlsPrivateKey != nil && len(freshMtlsPrivateKey) > 0 {
		// Сценарий А: Мы получили свежий mTLS ключ напрямую из аргументов фазы регистрации
		slog.Debug("Sealing fresh incoming mTLS private key payload under canonical DeviceKEK")
		newMtlsJSON, err = security.SealEnvelope(newDeviceKEK, freshMtlsPrivateKey, newMtlsAAD, security.AADSchemaDeviceMasterKey)
		if err != nil {
			return fmt.Errorf("failed to seal fresh mTLS private key under canonical device kek: %w", err)
		}
	} else if currentState.EncryptedMtlsPrivateKey != nil && len(*currentState.EncryptedMtlsPrivateKey) > 0 {
		// Сценарий Б: Нового ключа нет, мы просто перешифровываем уже существующий локальный mTLS ключ
		slog.Debug("Decrypting existing local mTLS private key via old DeviceKEK for migration code cascade")
		oldMtlsAAD := security.BuildDeviceMasterKeyAAD(currentState.UserID, currentState.DeviceID)
		rawMtlsPriv, err := security.OpenEnvelope(oldDeviceKEK, *currentState.EncryptedMtlsPrivateKey, oldMtlsAAD)
		if err != nil {
			return fmt.Errorf("failed to decrypt mTLS private key during reconcile: %w", err)
		}
		mtlsSecret := security.SecretBytes(rawMtlsPriv)

		newMtlsJSON, err = security.SealEnvelope(newDeviceKEK, mtlsSecret, newMtlsAAD, security.AADSchemaDeviceMasterKey)
		mtlsSecret.Destroy() // RAM Hygiene: Мгновенное выжигание
		if err != nil {
			return fmt.Errorf("failed to re-encrypt existing mTLS private key: %w", err)
		}
	}

	// 8. СБОРКА ФИНАЛЬНОГО КАНОНИЧЕСКОГО СОСТОЯНИЯ УСТРОЙСТВА
	serverURLStr := serverURL
	var finalMtlsPtr *[]byte = nil
	if len(newMtlsJSON) > 0 {
		finalMtlsPtr = &newMtlsJSON
	}

	updatedState := &repository.LocalDeviceState{
		ServerURL:                &serverURLStr,
		UserID:                   &serverUserIDStr,
		DeviceID:                 currentState.DeviceID,
		SshPublicKey:             currentState.SshPublicKey,
		AccountSalt:              canonicalSalt,
		DeviceMasterKeyEnvelope:  newDeviceEnvJSON,
		AccountBootstrapEnvelope: canonicalBootstrapEnvJSON,
		EncryptedMtlsPrivateKey:  finalMtlsPtr,
		ClientCertificate:        &serverCert,
		CreatedAt:                currentState.CreatedAt,
	}

	// 9. ФИКСАЦИЯ ИЗМЕНЕНИЙ В ЕДИНОЙ СУБД ТРАНЗАКЦИИ (Инвариант №15)
	slog.Info("Executing transacted atomic commit of updated state structure and records table")
	if err := s.deviceStore.ExecuteReconcileTransaction(ctx, updatedState, migratedRecords); err != nil {
		slog.Error("Critical database failure during transacted reconcile commit", "error", err)
		return fmt.Errorf("atomic transaction reconciliation failed: %w", err)
	}

	slog.Info("Reconciliation and re-encryption pipeline successfully finalized")
	return nil
}
