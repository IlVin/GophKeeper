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

// SQLiteDeviceStore реализует репозиторий управления состоянием синглтон-контейнера
// устройства и проведения атомарных транзакций миграции.
type SQLiteDeviceStore struct {
	db *sql.DB
}

// NewSQLiteDeviceStore конструирует новый экземпляр репозитория состояния устройства.
func NewSQLiteDeviceStore(db *sql.DB) *SQLiteDeviceStore {
	return &SQLiteDeviceStore{db: db}
}

// ReadDeviceState вычитывает текущую конфигурацию синглтона из таблицы device_state (id=1).
func (s *SQLiteDeviceStore) ReadDeviceState(ctx context.Context) (*repository.LocalDeviceState, error) {
	query := `
		SELECT server_url, user_id, device_id, ssh_public_key, account_salt, 
		       device_master_key_envelope, account_bootstrap_envelope, 
		       encrypted_mtls_private_key, client_certificate, created_at 
		FROM device_state 
		WHERE id = 1;`

	var state repository.LocalDeviceState
	var serverURLNull, userIDNull sql.NullString
	var cStr string

	err := s.db.QueryRowContext(ctx, query).Scan(
		&serverURLNull,
		&userIDNull,
		&state.DeviceID,
		&state.SshPublicKey,
		&state.AccountSalt,
		&state.DeviceMasterKeyEnvelope,
		&state.AccountBootstrapEnvelope,
		&state.EncryptedMtlsPrivateKey,
		&state.ClientCertificate,
		&cStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			slog.Debug("State query: device_state table empty (init required)")
			return nil, fmt.Errorf("environment not initialized: %w", err)
		}
		slog.Error("Critical Scan error reading device_state", "error", err)
		return nil, fmt.Errorf("scan state row: %w", err)
	}

	if serverURLNull.Valid {
		state.ServerURL = &serverURLNull.String
	}
	if userIDNull.Valid {
		state.UserID = &userIDNull.String
	}
	state.CreatedAt = cStr

	return &state, nil
}

// SaveDeviceState выполняет первичное сохранение оффлайн-конфигурации или её полную перезапись (UPSERT).
func (s *SQLiteDeviceStore) SaveDeviceState(ctx context.Context, state *repository.LocalDeviceState) error {
	query := `
		INSERT INTO device_state (
			id, server_url, user_id, device_id, ssh_public_key, account_salt, 
			device_master_key_envelope, account_bootstrap_envelope, 
			encrypted_mtls_private_key, client_certificate, created_at
		) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			server_url = EXCLUDED.server_url,
			user_id = EXCLUDED.user_id,
			device_id = EXCLUDED.device_id,
			ssh_public_key = EXCLUDED.ssh_public_key,
			account_salt = EXCLUDED.account_salt,
			device_master_key_envelope = EXCLUDED.device_master_key_envelope,
			account_bootstrap_envelope = EXCLUDED.account_bootstrap_envelope,
			encrypted_mtls_private_key = EXCLUDED.encrypted_mtls_private_key,
			client_certificate = EXCLUDED.client_certificate,
			created_at = EXCLUDED.created_at;`

	var serverURLNull sql.NullString
	if state.ServerURL != nil {
		serverURLNull.String = *state.ServerURL
		serverURLNull.Valid = true
	}

	var userIDNull sql.NullString
	if state.UserID != nil {
		userIDNull.String = *state.UserID
		userIDNull.Valid = true
	}

	slog.Debug("Writing singleton state to device_state")
	_, err := s.db.ExecContext(ctx, query,
		serverURLNull,
		userIDNull,
		state.DeviceID,
		state.SshPublicKey,
		state.AccountSalt,
		state.DeviceMasterKeyEnvelope,
		state.AccountBootstrapEnvelope,
		state.EncryptedMtlsPrivateKey,
		state.ClientCertificate,
		state.CreatedAt,
	)
	if err != nil {
		slog.Error("Failed to UPSERT device_state table", "error", err)
		return fmt.Errorf("save device_state: %w", err)
	}
	return nil
}

// ExecuteReconcileTransaction атомарно обновляет конфигурацию синглтона и всю таблицу records
// внутри единой изолированной транзакции SQLite для обеспечения целостности данных (Инвариант №15).
func (s *SQLiteDeviceStore) ExecuteReconcileTransaction(
	ctx context.Context,
	state *repository.LocalDeviceState,
	records []repository.EncryptedRecord,
) error {
	slog.Info("Starting isolated local container reconciliation transaction (Reconcile Transaction)")

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("open migration transaction: %w", err)
	}

	// Флаг для предотвращения ложного логирования ошибки Rollback при успешном Commit
	txCommitted := false
	defer func() {
		if !txCommitted {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				slog.Error("Critical failure: could not rollback transaction on emergency exit", "error", rollbackErr)
			}
		}
	}()

	// 1. Обновляем глобальное состояние устройства в device_state (id = 1)
	stateQuery := `
		UPDATE device_state SET
			server_url = ?,
			user_id = ?,
			account_salt = ?,
			device_master_key_envelope = ?,
			account_bootstrap_envelope = ?,
			encrypted_mtls_private_key = ?,
			client_certificate = ?
		WHERE id = 1;`

	var serverURLStr sql.NullString
	if state.ServerURL != nil {
		serverURLStr.String = *state.ServerURL
		serverURLStr.Valid = true
	}

	var userIDStr sql.NullString
	if state.UserID != nil {
		userIDStr.String = *state.UserID
		userIDStr.Valid = true
	}

	slog.Debug("Step 1: Updating global cryptographic singleton metadata")
	_, err = tx.ExecContext(ctx, stateQuery,
		serverURLStr,
		userIDStr,
		state.AccountSalt,
		state.DeviceMasterKeyEnvelope,
		state.AccountBootstrapEnvelope,
		state.EncryptedMtlsPrivateKey,
		state.ClientCertificate,
	)
	if err != nil {
		return fmt.Errorf("update device_state inside transaction: %w", err)
	}

	// 2. Если у нас были оффлайн-записи, атомарно перешифровываем и подменяем их под новый канонический вид
	if len(records) > 0 {
		slog.Debug("Step 2: Full cleanup of obsolete records table before batch insert", "count", len(records))
		if _, err = tx.ExecContext(ctx, `DELETE FROM records;`); err != nil {
			return fmt.Errorf("cleanup records before migration: %w", err)
		}

		recordQuery := `
			INSERT INTO records (id, user_id, name, type, envelope, created_at, updated_at, is_deleted)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?);`

		stmt, err := tx.PrepareContext(ctx, recordQuery)
		if err != nil {
			return fmt.Errorf("prepare records migration statement: %w", err)
		}

		stmtClosed := false
		defer func() {
			if !stmtClosed {
				_ = stmt.Close()
			}
		}()

		for _, rec := range records {
			var recUserID sql.NullString
			if rec.UserID != nil {
				recUserID.String = *rec.UserID
				recUserID.Valid = true
			}

			_, err = tx.Stmt(stmt).ExecContext(ctx,
				rec.ID,
				recUserID,
				rec.Name,
				rec.Type,
				rec.Envelope,
				rec.CreatedAt.Format(time.RFC3339Nano),
				rec.UpdatedAt.Format(time.RFC3339Nano),
				rec.IsDeleted,
			)
			if err != nil {
				return fmt.Errorf("batch insert migrated record %s: %w", rec.ID, err)
			}
		}

		if stmtCloseErr := stmt.Close(); stmtCloseErr != nil {
			slog.Error("Failed to close prepared records migration statement", "error", stmtCloseErr)
		}
		stmtClosed = true
	}

	// Фиксируем транзакцию на диске
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit migration transaction (Commit): %w", err)
	}
	txCommitted = true

	slog.Info("Reconciliation transaction successfully committed to disk, integrity guaranteed")
	return nil
}

// GetAllRecords вычитывает плоский список зашифрованных оффлайн-записей для пакетной ре-энкрипции.
func (s *SQLiteDeviceStore) GetAllRecords(ctx context.Context) ([]repository.EncryptedRecord, error) {
	query := `SELECT id, user_id, name, type, envelope, created_at, updated_at, is_deleted FROM records;`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		slog.Error("Failed to fetch all records for migration", "error", err)
		return nil, fmt.Errorf("fetch all records: %w", err)
	}
	defer rows.Close()

	var list []repository.EncryptedRecord
	for rows.Next() {
		var r repository.EncryptedRecord
		var uNull sql.NullString
		var cStr, uStr string
		var isDeleted int32

		if err := rows.Scan(&r.ID, &uNull, &r.Name, &r.Type, &r.Envelope, &cStr, &uStr, &isDeleted); err != nil {
			return nil, fmt.Errorf("scan re-encryption row: %w", err)
		}

		if uNull.Valid {
			r.UserID = &uNull.String
		}

		r.CreatedAt, err = time.Parse(time.RFC3339Nano, cStr)
		if err != nil {
			return nil, fmt.Errorf("parse created_at for record %s: %w", r.ID, err)
		}

		r.UpdatedAt, err = time.Parse(time.RFC3339Nano, uStr)
		if err != nil {
			return nil, fmt.Errorf("parse updated_at for record %s: %w", r.ID, err)
		}

		r.IsDeleted = isDeleted

		list = append(list, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate re-encryption rows: %w", err)
	}

	return list, nil
}
