package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"gophkeeper/internal/client/repository"
)

type SQLiteSecretStore struct {
	db *sql.DB
}

// NewSQLiteSecretStore создает новый экземпляр репозитория секретов
func NewSQLiteSecretStore(db *sql.DB) *SQLiteSecretStore {
	return &SQLiteSecretStore{db: db}
}

// Save атомарно создает или обновляет запись (UPSERT)
func (s *SQLiteSecretStore) Save(ctx context.Context, record *repository.EncryptedRecord) error {
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
		return fmt.Errorf("failed to insert/update record into sqlite: %w", err)
	}

	return nil
}

// GetByID вытягивает зашифрованную запись по её UUID
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
		return nil, nil // Возвращаем nil, если запись не найдена
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan record by id from sqlite: %w", err)
	}

	if userIDNull.Valid {
		r.UserID = &userIDNull.String
	}
	r.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
	r.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAtStr)

	return &r, nil
}

// GetByName вытягивает зашифрованную запись по текстовому имени для поиска
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
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan record by name from sqlite: %w", err)
	}

	if userIDNull.Valid {
		r.UserID = &userIDNull.String
	}
	r.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
	r.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAtStr)

	return &r, nil
}

// List возвращает плоский список легковесных метаданных для CLI-отображения
func (s *SQLiteSecretStore) List(ctx context.Context) ([]repository.RecordMetadata, error) {
	query := `SELECT id, name, type, updated_at FROM records ORDER BY updated_at DESC;`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
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
		m.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAtStr)
		list = append(list, m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error in records list: %w", err)
	}

	return list, nil
}

// Delete полностью вычищает строку записи по её ID
func (s *SQLiteSecretStore) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM records WHERE id = ?;`

	_, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete record from sqlite: %w", err)
	}

	return nil
}
