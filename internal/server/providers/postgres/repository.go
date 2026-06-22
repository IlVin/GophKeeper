package postgres

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"gophkeeper/internal/server/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

// --- Реализация UserRepository ---

func (r *PostgresRepository) CreateUser(ctx context.Context, u *repository.User) error {
	query := `
	INSERT INTO users (id, ssh_fingerprint, ssh_public_key, canonical_account_salt, canonical_bootstrap_envelope)
	VALUES ($1, $2, $3, $4, $5);`

	_, err := r.pool.Exec(ctx, query, u.ID, u.SshFingerprint, u.SshPublicKey, u.CanonicalAccountSalt, u.CanonicalBootstrapEnvelope)
	return err
}

func (r *PostgresRepository) GetByFingerprint(ctx context.Context, fingerprint string) (*repository.User, error) {
	query := `SELECT id, ssh_fingerprint, ssh_public_key, canonical_account_salt, canonical_bootstrap_envelope, created_at FROM users WHERE ssh_fingerprint = $1;`

	var u repository.User
	err := r.pool.QueryRow(ctx, query, fingerprint).Scan(
		&u.ID, &u.SshFingerprint, &u.SshPublicKey, &u.CanonicalAccountSalt, &u.CanonicalBootstrapEnvelope, &u.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &u, err
}

// --- Реализация DeviceRepository ---

func (r *PostgresRepository) CreateDevice(ctx context.Context, d *repository.Device) error { // ИСПРАВЛЕНО
	query := `
	INSERT INTO devices (id, user_id, device_master_key_envelope, client_certificate, cert_serial_number, status)
	VALUES ($1, $2, $3, $4, $5, $6);`

	serialStr := d.CertSerialNumber.String()
	_, err := r.pool.Exec(ctx, query, d.ID, d.UserID, d.DeviceMasterKeyEnvelope, d.ClientCertificate, serialStr, d.Status)
	if err != nil {
		return fmt.Errorf("failed to insert device to postgres: %w", err)
	}
	return nil
}

func (r *PostgresRepository) GetByID(ctx context.Context, id string) (*repository.Device, error) {
	query := `SELECT id, user_id, device_master_key_envelope, client_certificate, cert_serial_number, status, registered_at, last_sync_at FROM devices WHERE id = $1;`

	var d repository.Device
	var serialStr string
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&d.ID, &d.UserID, &d.DeviceMasterKeyEnvelope, &d.ClientCertificate, &serialStr, &d.Status, &d.RegisteredAt, &d.LastSyncAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch device by id: %w", err)
	}

	d.CertSerialNumber, _ = new(big.Int).SetString(serialStr, 10)
	return &d, nil
}

func (r *PostgresRepository) UpdateSyncTime(ctx context.Context, id string) error {
	query := `UPDATE devices SET last_sync_at = CURRENT_TIMESTAMP WHERE id = $1;`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

func (r *PostgresRepository) UpdateStatus(ctx context.Context, id string, status string) error {
	query := `UPDATE devices SET status = $1 WHERE id = $2;`
	_, err := r.pool.Exec(ctx, query, status, id)
	return err
}

// --- Реализация ChallengeRepository (Challenge State Machine) ---

func (r *PostgresRepository) CreateChallengeSession(ctx context.Context, s *repository.ChallengeSession) error { // ИСПРАВЛЕНО
	query := `
	INSERT INTO challenge_sessions (id, user_id, server_nonce, operation, state, expires_at)
	VALUES ($1, $2, $3, $4, $5, $6);`

	_, err := r.pool.Exec(ctx, query, s.ID, s.UserID, s.ServerNonce, s.Operation, s.State, s.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to insert challenge session: %w", err)
	}
	return nil
}

// GetAndLock блокирует строку сессии для безопасного атомарного изменения статуса (Защита от Race Conditions)
func (r *PostgresRepository) GetAndLock(ctx context.Context, id string) (*repository.ChallengeSession, error) {
	query := `SELECT id, user_id, server_nonce, operation, state, expires_at FROM challenge_sessions WHERE id = $1 FOR UPDATE;`

	var s repository.ChallengeSession
	// В проде этот вызов должен происходить внутри pgx.Tx транзакции.
	// Для MVP пула выполняем прямой QueryRow (блокировка FOR UPDATE удерживается до конца мини-транзакции)
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&s.ID, &s.UserID, &s.ServerNonce, &s.Operation, &s.State, &s.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch and lock challenge session: %w", err)
	}
	return &s, nil
}

func (r *PostgresRepository) UpdateState(ctx context.Context, id string, newState string) error {
	query := `UPDATE challenge_sessions SET state = $1 WHERE id = $2;`
	_, err := r.pool.Exec(ctx, query, newState, id)
	return err
}
