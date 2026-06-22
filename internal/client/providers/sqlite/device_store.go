package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"gophkeeper/internal/client/repository"
	"time"
)

type SQLiteDeviceStore struct {
	db *sql.DB
}

func NewSQLiteDeviceStore(db *sql.DB) *SQLiteDeviceStore {
	return &SQLiteDeviceStore{db: db}
}

func (s *SQLiteDeviceStore) SaveDeviceState(ctx context.Context, state *repository.LocalDeviceState) error {
	query := `
	INSERT INTO device_state (
		id, server_url, user_id, device_id, ssh_public_key, account_salt,
		device_master_key_envelope, account_bootstrap_envelope, 
		encrypted_mtls_private_key, client_certificate, created_at
	) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		server_url=excluded.server_url,
		user_id=excluded.user_id,
		device_id=excluded.device_id,
		ssh_public_key=excluded.ssh_public_key,
		account_salt=excluded.account_salt,
		device_master_key_envelope=excluded.device_master_key_envelope,
		account_bootstrap_envelope=excluded.account_bootstrap_envelope,
		encrypted_mtls_private_key=excluded.encrypted_mtls_private_key,
		client_certificate=excluded.client_certificate;`

	_, err := s.db.ExecContext(ctx, query,
		state.ServerURL,
		state.UserID,
		state.DeviceID,
		state.SshPublicKey,
		state.AccountSalt, // ДОБАВЛЕНО
		state.DeviceMasterKeyEnvelope,
		state.AccountBootstrapEnvelope,
		state.EncryptedMtlsPrivateKey,
		state.ClientCertificate,
		state.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("execute insert device_state: %w", err)
	}
	return nil
}

func (s *SQLiteDeviceStore) ReadDeviceState(ctx context.Context) (*repository.LocalDeviceState, error) {
	query := `
	SELECT server_url, user_id, device_id, ssh_public_key, account_salt,
	       device_master_key_envelope, account_bootstrap_envelope, 
	       encrypted_mtls_private_key, client_certificate, created_at
	FROM device_state WHERE id = 1;`

	var state repository.LocalDeviceState
	var serverURLNull, userIDNull sql.NullString
	var mtlsKeyNull, clientCertNull []byte

	err := s.db.QueryRowContext(ctx, query).Scan(
		&serverURLNull,
		&userIDNull,
		&state.DeviceID,
		&state.SshPublicKey,
		&state.AccountSalt, // ДОБАВЛЕНО
		&state.DeviceMasterKeyEnvelope,
		&state.AccountBootstrapEnvelope,
		&mtlsKeyNull,
		&clientCertNull,
		&state.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("device state is empty, please run init first")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query device_state: %w", err)
	}

	if serverURLNull.Valid {
		state.ServerURL = &serverURLNull.String
	}
	if userIDNull.Valid {
		state.UserID = &userIDNull.String
	}
	if len(mtlsKeyNull) > 0 {
		state.EncryptedMtlsPrivateKey = &mtlsKeyNull
	}
	if len(clientCertNull) > 0 {
		state.ClientCertificate = &clientCertNull
	}

	return &state, nil
}

// ExecuteReconcileTransaction атомарно обновляет конфигурацию синглтона и всю таблицу records
// внутри единой транзакции SQLite для обеспечения целостности при миграции (Инвариант №15)
func (s *SQLiteDeviceStore) ExecuteReconcileTransaction(
	ctx context.Context,
	state *repository.LocalDeviceState,
	records []repository.EncryptedRecord,
) error {
	// Открываем нативную транзакцию SQLite через пул s.db
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin reconciliation sqlite tx: %w", err)
	}
	// В случае паники или ошибки рантайма гарантируем откат состояния назад (Fail-Safe)
	defer func() { _ = tx.Rollback() }()

	// 1. Обновляем глобальное состояние устройства в device_state (id = 1)
	stateQuery := `
		UPDATE device_state SET
			user_id = $1,
			account_salt = $2,
			device_master_key_envelope = $3,
			account_bootstrap_envelope = $4,
			encrypted_mtls_private_key = $5,
			client_certificate = $6
		WHERE id = 1;`

	var userIDStr sql.NullString
	if state.UserID != nil {
		userIDStr.String = *state.UserID
		userIDStr.Valid = true
	}

	_, err = tx.ExecContext(ctx, stateQuery,
		userIDStr,
		state.AccountSalt,
		state.DeviceMasterKeyEnvelope,
		state.AccountBootstrapEnvelope,
		state.EncryptedMtlsPrivateKey,
		state.ClientCertificate,
	)
	if err != nil {
		return fmt.Errorf("reconcile tx: failed to update device_state: %w", err)
	}

	// 2. Если у нас были оффлайн-записи, атомарно обновляем их под новый UserID и MasterKey
	if len(records) > 0 {
		// Полностью вычищаем старую таблицу записей, так как у них изменились AAD и MasterKey
		if _, err = tx.ExecContext(ctx, `DELETE FROM records;`); err != nil {
			return fmt.Errorf("reconcile tx: failed to purge old records: %w", err)
		}

		recordQuery := `
			INSERT INTO records (id, user_id, name, type, envelope, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7);`

		stmt, err := tx.PrepareContext(ctx, recordQuery)
		if err != nil {
			return fmt.Errorf("reconcile tx: prepare statement failed: %w", err)
		}
		defer stmt.Close()

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
				rec.CreatedAt,
				rec.UpdatedAt,
			)
			if err != nil {
				return fmt.Errorf("reconcile tx: failed to insert migrated record %s: %w", rec.ID, err)
			}
		}
	}

	// Фиксируем транзакцию на диске. Теперь изменения применились атомарно!
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("reconcile tx: commit failed: %w", err)
	}

	return nil
}

func (s *SQLiteDeviceStore) GetAllRecords(ctx context.Context) ([]repository.EncryptedRecord, error) {
	// Вызываем чтение из таблицы records через пул s.db
	query := `SELECT id, user_id, name, type, envelope, created_at, updated_at FROM records;`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []repository.EncryptedRecord
	for rows.Next() {
		var r repository.EncryptedRecord
		var uNull sql.NullString
		var cStr, uStr string // ИСПРАВЛЕНО: Считываем даты как строки

		if err := rows.Scan(&r.ID, &uNull, &r.Name, &r.Type, &r.Envelope, &cStr, &uStr); err != nil {
			return nil, err
		}

		if uNull.Valid {
			r.UserID = &uNull.String
		}

		// ИСПРАВЛЕНО: Явно парсим текстовые строки SQLite в объекты time.Time
		r.CreatedAt, _ = time.Parse(time.RFC3339, cStr)
		r.UpdatedAt, _ = time.Parse(time.RFC3339, uStr)

		list = append(list, r)
	}
	return list, rows.Err()
}
