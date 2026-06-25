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
// Сохраняет is_deleted в том виде, в котором передан в record.
// Ответственность за установку правильного значения IsDeleted лежит на вызывающем коде.
func (s *SQLiteSecretStore) Save(ctx context.Context, record *repository.EncryptedRecord) error {
	if record == nil {
		return errors.New("cannot save nil record")
	}

	query := `
		INSERT INTO records (id, user_id, name, type, envelope, created_at, updated_at, is_deleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			user_id = excluded.user_id,
			name = excluded.name,
			type = excluded.type,
			envelope = excluded.envelope,
			updated_at = excluded.updated_at,
			is_deleted = excluded.is_deleted;`

	createdAtStr := record.CreatedAt.UTC().Format(time.RFC3339Nano)
	updatedAtStr := record.UpdatedAt.UTC().Format(time.RFC3339Nano)

	slog.Debug("Saving or updating local encrypted record",
		slog.String("record_id", record.ID),
		slog.Int64("is_deleted", int64(record.IsDeleted)),
	)
	_, err := s.db.ExecContext(ctx, query,
		record.ID,
		record.UserID,
		record.Name,
		record.Type,
		record.Envelope,
		createdAtStr,
		updatedAtStr,
		record.IsDeleted,
	)
	if err != nil {
		slog.ErrorContext(context.Background(), "Failed to UPSERT secret record",
			slog.String("record_id", record.ID),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to insert/update record into sqlite: %w", err)
	}

	return nil
}

// GetByID извлекает зашифрованный конверт записи из СУБД по её уникальному UUID.
// Возвращает только НЕ удаленные записи (is_deleted = 0).
func (s *SQLiteSecretStore) GetByID(ctx context.Context, id string) (*repository.EncryptedRecord, error) {
	query := `SELECT id, user_id, name, type, envelope, created_at, updated_at, is_deleted FROM records WHERE id = ? AND is_deleted = 0;`

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
		&r.IsDeleted,
	)
	if errors.Is(err, sql.ErrNoRows) {
		slog.Debug("GetByID query: record not found",
			slog.String("id", id),
		)
		return nil, nil
	}
	if err != nil {
		slog.ErrorContext(context.Background(), "Error reading row by ID from SQLite",
			slog.String("id", id),
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to scan record by id from sqlite: %w", err)
	}

	if userIDNull.Valid {
		r.UserID = &userIDNull.String
	}

	r.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at timestamp for record %s: %w", r.ID, err)
	}
	r.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at timestamp for record %s: %w", r.ID, err)
	}

	return &r, nil
}

// GetByName извлекает зашифрованный конверт записи по открытому текстовому имени для локального поиска.
// Возвращает только НЕ удаленные записи (is_deleted = 0).
func (s *SQLiteSecretStore) GetByName(ctx context.Context, name string) (*repository.EncryptedRecord, error) {
	query := `SELECT id, user_id, name, type, envelope, created_at, updated_at, is_deleted FROM records WHERE name = ? AND is_deleted = 0;`

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
		&r.IsDeleted,
	)
	if errors.Is(err, sql.ErrNoRows) {
		slog.Debug("GetByName query: record not found",
			slog.String("name", name),
		)
		return nil, nil
	}
	if err != nil {
		slog.ErrorContext(context.Background(), "Error reading row by name from SQLite",
			slog.String("name", name),
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to scan record by name from sqlite: %w", err)
	}

	if userIDNull.Valid {
		r.UserID = &userIDNull.String
	}

	r.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at timestamp for record %s: %w", r.ID, err)
	}
	r.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at timestamp for record %s: %w", r.ID, err)
	}

	return &r, nil
}

// List возвращает плоский список легковесных метаданных для CLI-отображения таблицы секретов.
// Возвращает только НЕ удаленные записи (is_deleted = 0).
func (s *SQLiteSecretStore) List(ctx context.Context) ([]repository.RecordMetadata, error) {
	query := `SELECT id, name, type, updated_at FROM records WHERE is_deleted = 0 ORDER BY updated_at DESC;`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		slog.ErrorContext(context.Background(), "Failed to read flat metadata list from SQLite",
			slog.Any("error", err),
		)
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

		m.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAtStr)
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

// Delete выполняет мягкое удаление записи, устанавливая флаг is_deleted = 1
// и обновляя временную метку updated_at.
func (s *SQLiteSecretStore) Delete(ctx context.Context, id string) error {
	query := `UPDATE records SET is_deleted = 1, updated_at = $1 WHERE id = $2;`

	// 1. Генерируем точное монотонное UTC-время на стороне рантайма Go
	// 2. Сериализуем его в канонический текстовый формат RFC3339 для SQLite
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)

	slog.Debug("Soft delete local record (is_deleted flag)",
		slog.String("id", id),
		slog.String("updated_at", nowStr),
	)

	_, err := s.db.ExecContext(ctx, query, nowStr, id)
	if err != nil {
		slog.ErrorContext(context.Background(), "Failed to soft delete secret record",
			slog.String("id", id),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to delete record from sqlite: %w", err)
	}

	return nil
}

// GetSyncMetadata вычитывает легковесную карту соответствий ID -> UpdatedAt для сетевой LWW сверки.
// ВАЖНО: Возвращает ВСЕ записи (включая удаленные) для корректной синхронизации.
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

		t, err := time.Parse(time.RFC3339Nano, uStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse sync updated_at string: %w", err)
		}
		meta[id] = t.UTC()
	}
	return meta, rows.Err()
}

// GetSyncMetadataWithDeleted вычитывает карту с метаданными включая is_deleted.
// ВАЖНО: Возвращает ВСЕ записи (включая удаленные) для корректной синхронизации.
func (s *SQLiteSecretStore) GetSyncMetadataWithDeleted(ctx context.Context) (map[string]repository.RecordVersionMeta, error) {
	query := `SELECT id, updated_at, is_deleted FROM records;`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch sync metadata map with deleted: %w", err)
	}
	defer rows.Close()

	meta := make(map[string]repository.RecordVersionMeta)
	for rows.Next() {
		var id, uStr string
		var isDeleted int32
		if err := rows.Scan(&id, &uStr, &isDeleted); err != nil {
			return nil, fmt.Errorf("failed to scan sync row metadata: %w", err)
		}

		t, err := time.Parse(time.RFC3339Nano, uStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse sync updated_at string: %w", err)
		}
		meta[id] = repository.RecordVersionMeta{
			UpdatedAt: t.UTC(),
			IsDeleted: isDeleted,
		}
	}
	return meta, rows.Err()
}

// SaveRaw выполняет слепой Upsert зашифрованного конверта, пришедшего с сервера при Pull-сессии.
// Обновление применится на диске только в том случае, если входящая дата строго свежее локальной.
// ВАЖНО: Сохраняет is_deleted в том виде, в котором пришло с сервера.
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

	slog.Debug("Network sync (SaveRaw): applying LWW envelope from cloud",
		slog.String("id", r.ID),
	)
	_, err := s.db.ExecContext(ctx, query,
		r.ID,
		userIDStr,
		r.Name,
		r.Type,
		r.Envelope,
		r.CreatedAt.Format(time.RFC3339Nano),
		r.UpdatedAt.Format(time.RFC3339Nano),
		r.IsDeleted,
	)
	if err != nil {
		slog.ErrorContext(context.Background(), "Failed to execute SaveRaw for incoming network packet",
			slog.String("id", r.ID),
			slog.Any("error", err),
		)
		return fmt.Errorf("failed to save raw synchronised record: %w", err)
	}
	return nil
}

// GetRawByID вычитывает сырой зашифрованный конверт для его отправки в облако при Push-сессии.
// ВАЖНО: Возвращает ВСЕ записи (включая удаленные) для корректной синхронизации.
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
		slog.ErrorContext(context.Background(), "Error calling GetRawByID for network push packet assembly",
			slog.String("id", id),
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to fetch raw record by id: %w", err)
	}

	if userIDNull.Valid {
		r.UserID = &userIDNull.String
	}

	r.CreatedAt, err = time.Parse(time.RFC3339Nano, cStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw created_at string: %w", err)
	}
	r.UpdatedAt, err = time.Parse(time.RFC3339Nano, uStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw updated_at string: %w", err)
	}

	return &r, nil
}
