package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"gophkeeper/internal/client/repository"
)

type SQLiteDeviceStore struct {
	db *sql.DB
}

func NewSQLiteDeviceStore(db *sql.DB) *SQLiteDeviceStore {
	return &SQLiteDeviceStore{db: db}
}

// ReadDeviceState вычитывает текущую конфигурацию синглтона из device_state (id=1)
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
		return nil, err
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

// SaveDeviceState выполняет первичное сохранение оффлайн-конфигурации или её перезапись
func (s *SQLiteDeviceStore) SaveDeviceState(ctx context.Context, state *repository.LocalDeviceState) error {
	query := `
		INSERT INTO device_state (
			id, server_url, user_id, device_id, ssh_public_key, account_salt, 
			device_master_key_envelope, account_bootstrap_envelope, 
			encrypted_mtls_private_key, client_certificate, created_at
		) VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
	return err
}

// ExecuteReconcileTransaction атомарно обновляет конфигурацию синглтона и всю таблицу records
// внутри единой транзакции SQLite для обеспечения целостности при миграции (Инвариант №15)
func (s *SQLiteDeviceStore) ExecuteReconcileTransaction(
	ctx context.Context,
	state *repository.LocalDeviceState,
	records []repository.EncryptedRecord,
) error {
	// Открываем нативную изолированную транзакцию SQLite через пул s.db
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin reconciliation sqlite tx: %w", err)
	}
	// В случае паники или непредвиденного сбоя рантайма гарантируем откат состояния назад (Fail-Safe)
	defer func() { _ = tx.Rollback() }()

	// 1. Обновляем глобальное состояние устройства в device_state (id = 1)
	// ЖЕСТКИЙ ИБ-КОНТРОЛЬ: Все 7 критических колонок выстроены строго по порядку параметров $1 - $7
	stateQuery := `
		UPDATE device_state SET
			server_url = $1,
			user_id = $2,
			account_salt = $3,
			device_master_key_envelope = $4,
			account_bootstrap_envelope = $5,
			encrypted_mtls_private_key = $6,
			client_certificate = $7
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

	// СВЕРКА ИНДЕКСОВ: Аргументы передаются в идеальном соответствии с SQL-шаблоном ($1 - $7)
	_, err = tx.ExecContext(ctx, stateQuery,
		serverURLStr,                   // $1 -> server_url
		userIDStr,                      // $2 -> user_id
		state.AccountSalt,              // $3 -> account_salt
		state.DeviceMasterKeyEnvelope,  // $4 -> device_master_key_envelope
		state.AccountBootstrapEnvelope, // $5 -> account_bootstrap_envelope
		state.EncryptedMtlsPrivateKey,  // $6 -> encrypted_mtls_private_key
		state.ClientCertificate,        // $7 -> client_certificate
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
				rec.CreatedAt.Format(time.RFC3339), // Приведение к текстовому ISO-канону для СУБД SQLite
				rec.UpdatedAt.Format(time.RFC3339),
			)
			if err != nil {
				return fmt.Errorf("reconcile tx: failed to insert migrated record %s: %w", rec.ID, err)
			}
		}
	}

	// Фиксируем транзакцию на диске. Теперь изменения применились атомарно и без сдвига данных!
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("reconcile tx: commit failed: %w", err)
	}

	return nil
}

// GetAllRecords вычитывает плоский список зашифрованных оффлайн-записей для пакетной ре-энкрипции
func (s *SQLiteDeviceStore) GetAllRecords(ctx context.Context) ([]repository.EncryptedRecord, error) {
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
		var cStr, uStr string // Считываем временные метки как строки для защиты от Scan error

		if err := rows.Scan(&r.ID, &uNull, &r.Name, &r.Type, &r.Envelope, &cStr, &uStr); err != nil {
			return nil, err
		}

		if uNull.Valid {
			r.UserID = &uNull.String
		}

		// Явно парсим текстовые RFC3339-строки SQLite в полноценные объекты time.Time Go-рантайма
		r.CreatedAt, _ = time.Parse(time.RFC3339, cStr)
		r.UpdatedAt, _ = time.Parse(time.RFC3339, uStr)

		list = append(list, r)
	}
	return list, rows.Err()
}
