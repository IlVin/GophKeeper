package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"gophkeeper/internal/client/repository"
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
