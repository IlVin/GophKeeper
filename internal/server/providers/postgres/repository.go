// Package postgres предоставляет реализации инфраструктурных адаптеров,
// репозиториев и кэш-провайдеров для взаимодействия с СУБД PostgreSQL.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"

	"gophkeeper/internal/server/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresRepository реализует централизованное управление реляционными сущностями
// экосистемы GophKeeper: пользователями, устройствами и сессиями челленджей.
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository конструирует новый экземпляр репозитория PostgresRepository.
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

// --- Реализация UserRepository ---

// CreateUser атомарно регистрирует доменную сущность нового аккаунта в PostgreSQL.
func (r *PostgresRepository) CreateUser(ctx context.Context, u *repository.User) error {
	slog.Debug("Executing PostgreSQL INSERT for user record entity alignment",
		slog.String("user_id", u.ID),
	)
	query := `
		INSERT INTO users (id, ssh_fingerprint, ssh_public_key, canonical_account_salt, canonical_bootstrap_envelope)
		VALUES ($1, $2, $3, $4, $5);
	`
	_, err := r.pool.Exec(ctx, query, u.ID, u.SshFingerprint, u.SshPublicKey, u.CanonicalAccountSalt, u.CanonicalBootstrapEnvelope)
	if err != nil {
		slog.ErrorContext(context.Background(), "PostgreSQL user entry persistence transaction failed",
			slog.String("user_id", u.ID),
			slog.Any("error", err),
		)
		return fmt.Errorf("repository create user transaction failed: %w", err)
	}
	return nil
}

// GetByFingerprint извлекает аккаунт пользователя по уникальному SHA256-хешу SSH-ключа.
func (r *PostgresRepository) GetByFingerprint(ctx context.Context, fingerprint string) (*repository.User, error) {
	slog.Debug("Executing PostgreSQL lookup by user public key SSH fingerprint",
		slog.String("fingerprint", fingerprint),
	)
	query := `
		SELECT id, ssh_fingerprint, ssh_public_key, canonical_account_salt, canonical_bootstrap_envelope, created_at 
		FROM users WHERE ssh_fingerprint = $1;
	`
	var u repository.User
	err := r.pool.QueryRow(ctx, query, fingerprint).Scan(
		&u.ID, &u.SshFingerprint, &u.SshPublicKey, &u.CanonicalAccountSalt, &u.CanonicalBootstrapEnvelope, &u.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		slog.ErrorContext(context.Background(), "PostgreSQL lookup by fingerprint failed",
			slog.String("fingerprint", fingerprint),
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("repository fingerprint lookup failed: %w", err)
	}
	return &u, nil
}

// --- Реализация DeviceRepository ---

// CreateDevice регистрирует метаданные mTLS-паспорта нового доверенного контейнера.
func (r *PostgresRepository) CreateDevice(ctx context.Context, d *repository.Device) error {
	slog.Debug("Executing PostgreSQL INSERT for client container mTLS device registry mapping",
		slog.String("device_id", d.ID),
	)
	query := `
		INSERT INTO devices (id, user_id, device_master_key_envelope, client_certificate, cert_serial_number, status)
		VALUES ($1, $2, $3, $4, $5, $6);
	`
	if d.CertSerialNumber == nil {
		return errors.New("cannot persist device entity: x509 certificate serial number is uninitialized")
	}

	serialStr := d.CertSerialNumber.String()
	_, err := r.pool.Exec(ctx, query, d.ID, d.UserID, d.DeviceMasterKeyEnvelope, d.ClientCertificate, serialStr, d.Status)
	if err != nil {
		slog.ErrorContext(context.Background(), "PostgreSQL device entity persistence transaction failed",
			slog.String("device_id", d.ID),
			slog.Any("error", err),
		)
		return fmt.Errorf("repository create device transaction failed: %w", err)
	}
	return nil
}

// GetByID извлекает метаданные контейнера по его уникальному аппаратному UUID.
func (r *PostgresRepository) GetByID(ctx context.Context, id string) (*repository.Device, error) {
	slog.Debug("Executing PostgreSQL lookup by hardware container device UUID",
		slog.String("device_id", id),
	)
	query := `
		SELECT id, user_id, device_master_key_envelope, client_certificate, cert_serial_number, status, registered_at, last_sync_at 
		FROM devices WHERE id = $1;
	`
	var d repository.Device
	var serialStr string
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&d.ID, &d.UserID, &d.DeviceMasterKeyEnvelope, &d.ClientCertificate, &serialStr, &d.Status, &d.RegisteredAt, &d.LastSyncAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		slog.ErrorContext(context.Background(), "PostgreSQL lookup by device UUID crashed",
			slog.String("device_id", id),
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("repository device lookup failed: %w", err)
	}

	var ok bool
	d.CertSerialNumber, ok = new(big.Int).SetString(serialStr, 10)
	if !ok {
		slog.ErrorContext(context.Background(), "PKI serialization failure: failed to reconstruct big.Int from database serial string",
			slog.String("serial", serialStr),
		)
		return nil, errors.New("repository big.Int serial number restoration failure")
	}

	return &d, nil
}

// UpdateSyncTime обновляет временную метку последней успешной репликации контейнера.
func (r *PostgresRepository) UpdateSyncTime(ctx context.Context, id string) error {
	query := `UPDATE devices SET last_sync_at = CURRENT_TIMESTAMP WHERE id = $1;`
	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		slog.ErrorContext(context.Background(), "PostgreSQL update sync timestamp query failed",
			slog.String("device_id", id),
			slog.Any("error", err),
		)
		return fmt.Errorf("repository update sync time failed: %w", err)
	}
	return nil
}

// UpdateStatus выполняет блокировку или отзыв mTLS прав контейнера (status = revoked).
func (r *PostgresRepository) UpdateStatus(ctx context.Context, id string, status string) error {
	query := `UPDATE devices SET status = $1 WHERE id = $2;`
	_, err := r.pool.Exec(ctx, query, status, id)
	if err != nil {
		slog.ErrorContext(context.Background(), "PostgreSQL update device status query failed",
			slog.String("device_id", id),
			slog.String("status", status),
			slog.Any("error", err),
		)
		return fmt.Errorf("repository update device status failed: %w", err)
	}
	return nil
}

// --- Реализация ChallengeRepository (Challenge State Machine) ---

// CreateChallengeSession инициализирует одноразовую сессию вызова для Zero-Knowledge проверки.
func (r *PostgresRepository) CreateChallengeSession(ctx context.Context, s *repository.ChallengeSession) error {
	slog.Debug("Executing PostgreSQL INSERT for single-use challenge token entity mapping",
		slog.String("session_id", s.ID),
	)
	query := `
		INSERT INTO challenge_sessions (id, user_id, server_nonce, operation, state, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6);
	`
	_, err := r.pool.Exec(ctx, query, s.ID, s.UserID, s.ServerNonce, s.Operation, s.State, s.ExpiresAt)
	if err != nil {
		slog.ErrorContext(context.Background(), "PostgreSQL challenge session token transaction failed",
			slog.String("session_id", s.ID),
			slog.Any("error", err),
		)
		return fmt.Errorf("repository create challenge session transaction failed: %w", err)
	}
	return nil
}

// ConsumeChallengeSession - МУЛЬТИОПЕРАЦИОННЫЙ ИБ-БАРЬЕР (Замена небезопасного GetAndLock).
//
// Метод атомарно внутри ЧЕСТНОЙ ACID-транзакции извлекает сессию, верифицирует статус 'Unused'
// и МГНОВЕННО переводит её в состояние 'Used' в рамках единого COMMIT. Полностью ликвидирует
// возможность конкурентных Replay-атак (Double Spending) обхода mTLS.
func (r *PostgresRepository) ConsumeChallengeSession(ctx context.Context, id string) (*repository.ChallengeSession, error) {
	slog.Debug("Executing atomic multi-operational transaction for safe challenge token consumption",
		slog.String("session_id", id),
	)

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		slog.ErrorContext(context.Background(), "Failed to initiate database atomic transaction block for safe challenge consumption",
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to begin atomic challenge session transaction: %w", err)
	}

	txCommitted := false
	defer func() {
		if !txCommitted {
			_ = tx.Rollback(ctx)
		}
	}()

	query := `
		SELECT id, user_id, server_nonce, operation, state, expires_at 
		FROM challenge_sessions WHERE id = $1 FOR UPDATE;
	`
	var s repository.ChallengeSession
	err = tx.QueryRow(ctx, query, id).Scan(&s.ID, &s.UserID, &s.ServerNonce, &s.Operation, &s.State, &s.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		slog.ErrorContext(context.Background(), "Row locking failed inside PostgreSQL FOR UPDATE challenge sub-transaction",
			slog.String("session_id", id),
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to fetch and lock challenge session: %w", err)
	}

	// Если сессия валидна, мгновенно выжигаем её прямо внутри транзакции
	if s.State == "Unused" {
		slog.Debug("Atomic challenge state transition validation approved, executing state update to Used",
			slog.String("session_id", id),
		)
		_, err = tx.Exec(ctx, "UPDATE challenge_sessions SET state = 'Used' WHERE id = $1;", id)
		if err != nil {
			slog.ErrorContext(context.Background(), "Failed to update challenge state sub-transaction inside active commit layout",
				slog.String("session_id", id),
				slog.Any("error", err),
			)
			return nil, fmt.Errorf("failed to update challenge session state atomic: %w", err)
		}
		s.State = "Used" // Синхронизируем возвращаемый DTO-объект рантайма
	}

	if err = tx.Commit(ctx); err != nil {
		slog.ErrorContext(context.Background(), "PostgreSQL atomic transaction commit crashed for safe challenge token consumption",
			slog.String("session_id", id),
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to commit challenge consumption transaction: %w", err)
	}
	txCommitted = true

	return &s, nil
}

// UpdateState выполняет принудительный перевод сессии в статус 'Expired' или 'Completed'.
func (r *PostgresRepository) UpdateState(ctx context.Context, id string, newState string) error {
	query := `UPDATE challenge_sessions SET state = $1 WHERE id = $2;`
	_, err := r.pool.Exec(ctx, query, newState, id)
	if err != nil {
		slog.ErrorContext(context.Background(), "PostgreSQL challenge session state transition failure",
			slog.String("session_id", id),
			slog.String("new_state", newState),
			slog.Any("error", err),
		)
		return fmt.Errorf("repository update challenge state failed: %w", err)
	}
	return nil
}
