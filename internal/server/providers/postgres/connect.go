package postgres

import (
	"context"
	"fmt"
	"time"

	"gophkeeper/internal/server/config"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultMaxConns        = 25
	defaultMinConns        = 5
	defaultMaxConnLifetime = 15 * time.Minute
	defaultMaxConnIdleTime = 5 * time.Minute
	defaultDialTimeout     = 5 * time.Second
)

// Connect открывает нативный высокопроизводительный пул соединений к PostgreSQL
// и выполняет проверку связи (Ping) в рамках контекста.
func Connect(ctx context.Context, cfg config.StorageConfig) (*pgxpool.Pool, error) {
	if cfg.PostgresDSN == "" {
		return nil, fmt.Errorf("postgres dsn configuration is empty")
	}

	// Парсим DSN строку в типизированную конфигурацию pgx
	poolConfig, err := pgxpool.ParseConfig(cfg.PostgresDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse postgres dsn: %w", err)
	}

	// Настраиваем параметры пула "по образу и подобию" наших старых лимитов
	poolConfig.MaxConns = defaultMaxConns
	poolConfig.MinConns = defaultMinConns
	poolConfig.MaxConnLifetime = defaultMaxConnLifetime
	poolConfig.MaxConnIdleTime = defaultMaxConnIdleTime

	// Конфигурируем внутренний таймаут на установление TCP-сессии
	poolConfig.ConnConfig.ConnectTimeout = defaultDialTimeout

	// Инициализируем пул соединений
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create postgres pool: %w", err)
	}

	// Обязательно пингуем базу для проверки сетевой доступности и авторизации
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping postgres pool: %w", err)
	}

	return pool, nil
}
