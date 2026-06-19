package repository

import (
	"context"
	"time"
)

// EncryptedRecord представляет модель защищенного секрета, готовую к сохранению в БД.
// Вся конфиденциальная информация находится внутри запечатанного Envelope в виде JSON-байтов.
type EncryptedRecord struct {
	ID        string  // UUID записи, генерируется клиентом
	UserID    *string // Ссылка на владельца (NULL, если оффлайн-контейнер)
	Name      string  // Открытое имя для локального поиска и вывода в list
	Type      string  // Тип записи (credentials, binary, text, card)
	Envelope  []byte  // JSON-байты структуры crypto.Envelope (шифртекст + nonce + tag)
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RecordMetadata возвращает легковесную информацию о секрете для команды list
type RecordMetadata struct {
	ID        string
	Name      string
	Type      string
	UpdatedAt time.Time
}

// SecretStore определяет методы долгосрочного хранения зашифрованных записей
type SecretStore interface {
	// Save сохраняет новую запись или атомарно обновляет существующую
	Save(ctx context.Context, record *EncryptedRecord) error

	// GetByID извлекает зашифрованный конверт по его уникальному UUID
	GetByID(ctx context.Context, id string) (*EncryptedRecord, error)

	// GetByName извлекает зашифрованный конверт по его текстовому имени (для поиска)
	GetByName(ctx context.Context, name string) (*EncryptedRecord, error)

	// List returns метаданные всех записей для текущего контейнера (без чтения payload)
	List(ctx context.Context) ([]RecordMetadata, error)

	// Delete удаляет запись из локального хранилища по её ID
	Delete(ctx context.Context, id string) error
}
