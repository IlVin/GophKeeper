// Package repository предоставляет абстрактные интерфейсы и доменные структуры
// данных для взаимодействия со слоем персистентного хранения GophKeeper.
package repository

import (
	"context"
)

// LocalDeviceState инкапсулирует полное криптографическое и сетевое состояние
// локального синглтон-контейнера клиентского устройства.
//
// Структура содержит корневые ключи, соли и запечатанные конверты мастер-ключа,
// обеспечивая оффлайн-автономию и контролируемый доступ к сетевой синхронизации.
type LocalDeviceState struct {
	// ServerURL определяет адрес целевого gRPC-сервера GophKeeper (NULL до этапа register).
	ServerURL *string

	// UserID содержит уникальный сетевой UUID пользователя, привязанный сервером (NULL до register).
	UserID *string

	// DeviceID содержит вечный уникальный UUID текущего локального контейнера.
	DeviceID string

	// SshPublicKey хранит оригинальный бинарный маршал-блоб публичного ключа OpenSSH.
	SshPublicKey []byte

	// AccountSalt хранит криптографическую соль вывода ключей (строго 32 байта).
	AccountSalt []byte

	// DeviceMasterKeyEnvelope хранит конверт AccountMasterKey, зашифрованный под DeviceKEK.
	DeviceMasterKeyEnvelope []byte

	// AccountBootstrapEnvelope хранит конверт AccountMasterKey, зашифрованный под AccountUnlockKey.
	AccountBootstrapEnvelope []byte

	// EncryptedMtlsPrivateKey хранит mTLS закрытый ключ устройства, запечатанный под DeviceKEK.
	EncryptedMtlsPrivateKey *[]byte

	// ClientCertificate хранит выданный сервером x509 DER mTLS паспорт устройства.
	ClientCertificate *[]byte

	// CreatedAt содержит временную метку создания контейнера в формате UTC ISO8601.
	CreatedAt string
}

// Destroy осуществляет превентивное выжигание конфиденциальных бинарных данных соли
// и ссылок на структуры внутри LocalDeviceState для соблюдения RAM Hygiene.
func (l *LocalDeviceState) Destroy() {
	if l == nil {
		return
	}
	// Принудительно зануляем массив соли аккаунта
	for i := range l.AccountSalt {
		l.AccountSalt[i] = 0
	}
	l.SshPublicKey = nil
	l.DeviceMasterKeyEnvelope = nil
	l.AccountBootstrapEnvelope = nil
	l.EncryptedMtlsPrivateKey = nil
	l.ClientCertificate = nil
}

// DeviceStore определяет строгий абстрактный контракт для работы с глобальным состоянием
// синглтон-контейнера клиентского устройства и проведения атомарных миграций согласования.
type DeviceStore interface {
	// ReadDeviceState вычитывает текущую конфигурацию синглтона из таблицы device_state.
	ReadDeviceState(ctx context.Context) (*LocalDeviceState, error)

	// SaveDeviceState выполняет первичное сохранение оффлайн-конфигурации или её перезапись (UPSERT).
	SaveDeviceState(ctx context.Context, state *LocalDeviceState) error

	// GetAllRecords вычитывает плоский список зашифрованных оффлайн-записей для пакетной ре-энкрипции.
	// Метод необходим сервису InitService для проведения каскадной миграции Reconcile.
	GetAllRecords(ctx context.Context) ([]EncryptedRecord, error)

	// ExecuteReconcileTransaction атомарно фиксирует обновленное состояние синглтона
	// и полностью подменяет таблицу records в рамках единой ACID-транзакции хранилища.
	ExecuteReconcileTransaction(ctx context.Context, state *LocalDeviceState, records []EncryptedRecord) error
}
