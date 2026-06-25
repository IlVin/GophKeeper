// Package postgres предоставляет реализации инфраструктурных адаптеров,
// репозиториев и кэш-провайдеров для взаимодействия с СУБД PostgreSQL.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gophkeeper/internal/server/config"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultMaxConns        = int32(25)
	defaultMinConns        = int32(5)
	defaultMaxConnLifetime = 15 * time.Minute
	defaultMaxConnIdleTime = 5 * time.Minute
	defaultDialTimeout     = 5 * time.Second
)

// Connect открывает нативный высокопроизводительный пул соединений к PostgreSQL,
// настраивает его лимиты и выполняет обязательную сетевую проверку связи (Ping).
func Connect(ctx context.Context, cfg config.StorageConfig) (*pgxpool.Pool, error) {
	if cfg.PostgresDSN == "" {
		return nil, errors.New("postgres dsn configuration string is empty")
	}

	slog.Debug("Parsing PostgreSQL DSN connection parameters layout")
	poolConfig, err := pgxpool.ParseConfig(cfg.PostgresDSN)
	if err != nil {
		slog.ErrorContext(context.Background(), "Failed to parse provided PostgreSQL DSN string format",
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to parse postgres dsn: %w", err)
	}

	// Интегрируем динамические параметры из config.StorageConfig
	if cfg.MaxConns > 0 {
		poolConfig.MaxConns = cfg.MaxConns
	} else {
		poolConfig.MaxConns = defaultMaxConns
	}

	if cfg.MinConns > 0 {
		poolConfig.MinConns = cfg.MinConns
	} else {
		poolConfig.MinConns = defaultMinConns
	}

	poolConfig.MaxConnLifetime = defaultMaxConnLifetime
	poolConfig.MaxConnIdleTime = defaultMaxConnIdleTime

	// Конфигурируем внутренний ИБ-таймаут на установление первичной TCP-сессии
	poolConfig.ConnConfig.ConnectTimeout = defaultDialTimeout

	slog.Info("Initializing PostgreSQL client connection pool",
		"max_conns", poolConfig.MaxConns,
		"min_conns", poolConfig.MinConns,
	)

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		slog.ErrorContext(context.Background(), "PostgreSQL pool allocation factory crashed",
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to create postgres pool: %w", err)
	}

	// Обязательно пингуем базу для проверки сетевой доступности и авторизации (Fail-Fast)
	slog.Debug("Executing diagnostic network ping against PostgreSQL cluster nodes")
	if err = pool.Ping(ctx); err != nil {
		slog.ErrorContext(context.Background(), "Diagnostic ping failed: PostgreSQL node is unreachable or auth rejected",
			slog.Any("error", err),
		)
		pool.Close() // Защита от утечки RAM-дескрипторов
		return nil, fmt.Errorf("failed to ping postgres pool: %w", err)
	}

	slog.Info("Successfully established steady connection pool with PostgreSQL cluster")
	return pool, nil
}
