// Package sqlite предоставляет низкоуровневые ИБ-драйверы, миграции и репозитории
// для управления зашифрованным локальным хранилищем СУБД SQLite.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gophkeeper/internal/client/repository"
)

// SQLiteSecretStore реализует интерфейс репозитория SecretStore для работы
// со структурами запечатанных крипто-конвертов пользователей в СУБД SQLite.
type SQLiteSecretStore struct {
	db *sql.DB
}

// NewSQLiteSecretStore создает новый экземпляр репозитория секретов.
func NewSQLiteSecretStore(db *sql.DB) *SQLiteSecretStore {
	return &SQLiteSecretStore{db: db}
}

// Save атомарно создает новую зашифрованную запись или обновляет существующую (UPSERT).
func (s *SQLiteSecretStore) Save(ctx context.Context, record *repository.EncryptedRecord) error {
	if record == nil {
		return errors.New("cannot save nil record")
	}

	query := `
		INSERT INTO records (id, user_id, name, type, envelope, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			user_id = excluded.user_id,
			name = excluded.name,
			type = excluded.type,
			envelope = excluded.envelope,
			updated_at = excluded.updated_at;`

	createdAtStr := record.CreatedAt.UTC().Format(time.RFC3339)
	updatedAtStr := record.UpdatedAt.UTC().Format(time.RFC3339)

	slog.Debug("Сохранение или обновление локальной зашифрованной записи", "record_id", record.ID)
	_, err := s.db.ExecContext(ctx, query,
		record.ID,
		record.UserID,
		record.Name,
		record.Type,
		record.Envelope,
		createdAtStr,
		updatedAtStr,
	)
	if err != nil {
		slog.Error("Не удалось выполнить UPSERT секретной записи", "record_id", record.ID, "error", err)
		return fmt.Errorf("failed to insert/update record into sqlite: %w", err)
	}

	return nil
}

// GetByID извлекает зашифрованный конверт записи из СУБД по её уникальному UUID.
func (s *SQLiteSecretStore) GetByID(ctx context.Context, id string) (*repository.EncryptedRecord, error) {
	query := `SELECT id, user_id, name, type, envelope, created_at, updated_at FROM records WHERE id = ?;`

	var r repository.EncryptedRecord
	var userIDNull sql.NullString
	var createdAtStr, updatedAtStr string

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&r.ID,
		&userIDNull,
		&r.Name,
		&r.Type,
		&r.Envelope,
		&createdAtStr,
		&updatedAtStr,
	)
	if errors.Is(err, sql.ErrNoRows) {
		slog.Debug("Запрос GetByID: запись не найдена", "id", id)
		return nil, nil
	}
	if err != nil {
		slog.Error("Ошибка чтения строки по ID из SQLite", "id", id, "error", err)
		return nil, fmt.Errorf("failed to scan record by id from sqlite: %w", err)
	}

	if userIDNull.Valid {
		r.UserID = &userIDNull.String
	}

	r.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at timestamp for record %s: %w", r.ID, err)
	}
	r.UpdatedAt, err = time.Parse(time.RFC3339, updatedAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at timestamp for record %s: %w", r.ID, err)
	}

	return &r, nil
}

// GetByName извлекает зашифрованный конверт записи по открытому текстовому имени для локального поиска.
func (s *SQLiteSecretStore) GetByName(ctx context.Context, name string) (*repository.EncryptedRecord, error) {
	query := `SELECT id, user_id, name, type, envelope, created_at, updated_at FROM records WHERE name = ?;`

	var r repository.EncryptedRecord
	var userIDNull sql.NullString
	var createdAtStr, updatedAtStr string

	err := s.db.QueryRowContext(ctx, query, name).Scan(
		&r.ID,
		&userIDNull,
		&r.Name,
		&r.Type,
		&r.Envelope,
		&createdAtStr,
		&updatedAtStr,
	)
	if errors.Is(err, sql.ErrNoRows) {
		slog.Debug("Запрос GetByName: запись не найдена", "name", name)
		return nil, nil
	}
	if err != nil {
		slog.Error("Ошибка чтения строки по имени из SQLite", "name", name, "error", err)
		return nil, fmt.Errorf("failed to scan record by name from sqlite: %w", err)
	}

	if userIDNull.Valid {
		r.UserID = &userIDNull.String
	}

	r.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at timestamp for record %s: %w", r.ID, err)
	}
	r.UpdatedAt, err = time.Parse(time.RFC3339, updatedAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at timestamp for record %s: %w", r.ID, err)
	}

	return &r, nil
}

// List возвращает плоский список легковесных метаданных для CLI-отображения таблицы секретов.
func (s *SQLiteSecretStore) List(ctx context.Context) ([]repository.RecordMetadata, error) {
	query := `SELECT id, name, type, updated_at FROM records ORDER BY updated_at DESC;`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		slog.Error("Не удалось вычитать плоский список метаданных из SQLite", "error", err)
		return nil, fmt.Errorf("failed to query records list from sqlite: %w", err)
	}
	defer rows.Close()

	var list []repository.RecordMetadata
	for rows.Next() {
		var m repository.RecordMetadata
		var updatedAtStr string
		if err := rows.Scan(&m.ID, &m.Name, &m.Type, &updatedAtStr); err != nil {
			return nil, fmt.Errorf("failed to scan record metadata row: %w", err)
		}

		m.UpdatedAt, err = time.Parse(time.RFC3339, updatedAtStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse updated_at timestamp in list loop: %w", err)
		}
		list = append(list, m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error in records list: %w", err)
	}

	return list, nil
}

// Delete полностью вычищает строку записи и её зашифрованный конверт по её ID.
func (s *SQLiteSecretStore) Delete(ctx context.Context, id string) error {
	query := `UPDATE records SET is_deleted = 1, updated_at = $1 WHERE id = $2;`

	// 1. Генерируем точное монотонное UTC-время на стороне рантайма Go
	// 2. Сериализуем его в канонический текстовый формат RFC3339 для SQLite
	nowStr := time.Now().UTC().Format(time.RFC3339)

	slog.Debug("Мягкое удаление локальной записи (флаг is_deleted)", "id", id, "updated_at", nowStr)

	_, err := s.db.ExecContext(ctx, query, nowStr, id)
	if err != nil {
		slog.Error("Не удалось выполнить DELETE секретной записи", "id", id, "error", err)
		return fmt.Errorf("failed to delete record from sqlite: %w", err)
	}

	return nil
}

// GetSyncMetadata вычитывает легковесную карту соответствий ID -> UpdatedAt для сетевой LWW сверки.
func (s *SQLiteSecretStore) GetSyncMetadata(ctx context.Context) (map[string]time.Time, error) {
	query := `SELECT id, updated_at FROM records;`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch sync metadata map: %w", err)
	}
	defer rows.Close()

	meta := make(map[string]time.Time)
	for rows.Next() {
		var id, uStr string
		if err := rows.Scan(&id, &uStr); err != nil {
			return nil, fmt.Errorf("failed to scan sync row metadata: %w", err)
		}

		t, err := time.Parse(time.RFC3339, uStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse sync updated_at string: %w", err)
		}
		meta[id] = t.UTC()
	}
	return meta, rows.Err()
}

// SaveRaw выполняет слепой Upsert зашифрованного конверта, пришедшего с сервера при Pull-сессии.
// Обновление применится на диске только в том случае, если входящая дата строго свежее локальной.
func (s *SQLiteSecretStore) SaveRaw(ctx context.Context, r *repository.EncryptedRecord) error {
	query := `
		INSERT INTO records (id, user_id, name, type, envelope, created_at, updated_at, is_deleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO
			UPDATE SET
				user_id = EXCLUDED.user_id,
				name = EXCLUDED.name,
				type = EXCLUDED.type,
				envelope = EXCLUDED.envelope,
				created_at = EXCLUDED.created_at,
				updated_at = EXCLUDED.updated_at,
				is_deleted = EXCLUDED.is_deleted
			WHERE EXCLUDED.updated_at > records.updated_at;`

	var userIDStr sql.NullString
	if r.UserID != nil {
		userIDStr.String = *r.UserID
		userIDStr.Valid = true
	}

	// Извлекаем статус удаления из доменной модели (предполагается наличие поля IsDeleted типа int)
	// Если в вашей структуре EncryptedRecord поле называется по-другому, адаптируйте имя:
	isDeletedVal := r.IsDeleted

	slog.Debug("Сетевая синхронизация (SaveRaw): применение LWW конверта из облака", "id", r.ID)
	_, err := s.db.ExecContext(ctx, query,
		r.ID,
		userIDStr,
		r.Name,
		r.Type,
		r.Envelope,
		r.CreatedAt.Format(time.RFC3339),
		r.UpdatedAt.Format(time.RFC3339),
		isDeletedVal,
	)
	if err != nil {
		slog.Error("Не удалось выполнить SaveRaw для входящего сетевого пакета", "id", r.ID, "error", err)
		return fmt.Errorf("failed to save raw synchronised record: %w", err)
	}
	return nil
}

// GetRawByID вычитывает сырой зашифрованный конверт для его отправки в облако при Push-сессии.
func (s *SQLiteSecretStore) GetRawByID(ctx context.Context, id string) (*repository.EncryptedRecord, error) {
	query := `SELECT id, user_id, name, type, envelope, created_at, updated_at, is_deleted FROM records WHERE id = ?;`

	var r repository.EncryptedRecord
	var userIDNull sql.NullString
	var cStr, uStr string

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&r.ID, &userIDNull, &r.Name, &r.Type, &r.Envelope, &cStr, &uStr, &r.IsDeleted,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		slog.Error("Ошибка вызова GetRawByID для сборки сетевого push-пакета", "id", id, "error", err)
		return nil, fmt.Errorf("failed to fetch raw record by id: %w", err)
	}

	if userIDNull.Valid {
		r.UserID = &userIDNull.String
	}

	r.CreatedAt, err = time.Parse(time.RFC3339, cStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw created_at string: %w", err)
	}
	r.UpdatedAt, err = time.Parse(time.RFC3339, uStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw updated_at string: %w", err)
	}

	return &r, nil
}
