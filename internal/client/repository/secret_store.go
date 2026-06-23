// Package repository предоставляет абстрактные интерфейсы и доменные структуры
// данных для взаимодействия со слоем персистентного хранения GophKeeper.
package repository

import (
	"context"
	"time"
)

// EncryptedRecord представляет модель полностью зашифрованного пользовательского секрета,
// готовую к сохранению в репозитории или передаче по сети.
//
// Вся конфиденциальная полезная нагрузка и пользовательские метаданные инкапсулированы
// внутри бинарного конверта Envelope для исключения рисков Metadata Leakage.
type EncryptedRecord struct {
	// ID содержит уникальный детерминированный UUID v5 записи, генерируемый на базе её имени.
	ID string

	// UserID содержит ссылку на UUID канонического владельца в облаке (NULL, если оффлайн).
	UserID *string

	// Name содержит открытое имя записи, используемое для поиска и индексации в СУБД.
	Name string

	// Type определяет категорию секрета (credentials, binary, text, card).
	Type string

	// Envelope хранит сериализованные JSON-байты структуры крипто-конверта (шифртекст + nonce + Poly1305 tag).
	Envelope []byte

	// CreatedAt содержит временную метку создания записи в формате UTC.
	CreatedAt time.Time

	// UpdatedAt содержит временную метку последней модификации записи (базис для LWW-репликации).
	UpdatedAt time.Time

	// IsDeleted метка удаленности
	IsDeleted int32
}

// Destroy осуществляет превентивную очистку ссылок и бинарных массивов структуры
// EncryptedRecord в куче рантайма для соблюдения правил RAM Hygiene.
func (e *EncryptedRecord) Destroy() {
	if e == nil {
		return
	}
	e.Envelope = nil
	e.UserID = nil
}

// RecordMetadata возвращает легковесную информацию о секрете, исключая чтение
// криптографического конверта, для быстрого рендеринга таблиц в команде list.
type RecordMetadata struct {
	// ID содержит уникальный UUID записи.
	ID string

	// Name содержит открытое имя записи для отображения оператору.
	Name string

	// Type содержит категорию секрета для текстового рендеринга.
	Type string

	// UpdatedAt содержит локальное время последней модификации.
	UpdatedAt time.Time
}

// SecretStore определяет методы долгосрочного долговечного хранения,
// поиска, деструкции и распределенной LWW-синхронизации зашифрованных записей.
type SecretStore interface {
	// Save сохраняет новую запись или атомарно обновляет существующую (UPSERT).
	Save(ctx context.Context, record *EncryptedRecord) error

	// GetByID извлекает зашифрованный конверт из СУБД по его уникальному UUID.
	GetByID(ctx context.Context, id string) (*EncryptedRecord, error)

	// GetByName извлекает зашифрованный конверт по его уникальному текстовому имени.
	GetByName(ctx context.Context, name string) (*EncryptedRecord, error)

	// List возвращает легковесные метаданные всех записей для CLI-отображения таблицы (без чтения payload).
	List(ctx context.Context) ([]RecordMetadata, error)

	// Delete безвозвратно удаляет строку записи из локального хранилища по её ID.
	Delete(ctx context.Context, id string) error

	// GetSyncMetadata вычитывает легковесную карту соответствий ID -> UpdatedAt для сетевой LWW сверки версий.
	GetSyncMetadata(ctx context.Context) (map[string]time.Time, error)

	// SaveRaw выполняет слепой Upsert зашифрованного конверта, полученного от сервера при Pull-синхронизации.
	// Обновление применится на диске только в том случае, если входящая дата строго свежее локальной.
	SaveRaw(ctx context.Context, record *EncryptedRecord) error

	// GetRawByID вычитывает сырой зашифрованный конверт для его отправки в облако при Push-сессии синхронизации.
	GetRawByID(ctx context.Context, id string) (*EncryptedRecord, error)
}
