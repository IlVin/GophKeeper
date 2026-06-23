// Package postgres предоставляет реализации инфраструктурных адаптеров,
// репозиториев и кэш-провайдеров для взаимодействия с СУБД PostgreSQL.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/acme/autocert"
)

// pgxPoolIface объявляет строго минимальный набор методов пула соединений,
// необходимых подсистеме распределенного кэширования Let's Encrypt.
//
// Интерфейс спроектирован для обеспечения 100% покрытия юнит-тестами через pgxmock.
type pgxPoolIface interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// PostgresCache реализует контракт autocert.Cache на базе СУБД PostgreSQL.
// Обеспечивает персистентный шеринг TLS-сертификатов Let's Encrypt в кластере серверов.
type PostgresCache struct {
	pool pgxPoolIface
}

// NewPostgresCache конструирует новый экземпляр провайдера кэша PostgresCache.
func NewPostgresCache(pool pgxPoolIface) *PostgresCache {
	return &PostgresCache{pool: pool}
}

// Get извлекает бинарные данные PEM-сертификата Let's Encrypt по его текстовому ключу.
func (p *PostgresCache) Get(ctx context.Context, key string) ([]byte, error) {
	slog.Debug("Executing ACME Let's Encrypt cache lookup operation", "key", key)
	query := `SELECT data FROM acme_cache WHERE key = $1`
	var data []byte

	err := p.pool.QueryRow(ctx, query, key).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		slog.Debug("ACME cache miss tracking token", "key", key)
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		slog.Error("Database query failed inside ACME cache extraction phase", "key", key, "error", err)
		return nil, fmt.Errorf("pgx acme cache get failed: %w", err)
	}

	return data, nil
}

// Put атомарно сохраняет или обновляет бинарный PEM-блок сертификата в таблице acme_cache.
func (p *PostgresCache) Put(ctx context.Context, key string, data []byte) error {
	slog.Info("Publishing updated Let's Encrypt TLS certificate block to PostgreSQL cache", "key", key)

	// ИСПРАВЛЕНО: Убран избыточный ручной накат дат.
	// Время модификации теперь канонично выставляется триггером trigger_update_acme_cache_timestamp в СУБД
	query := `
		INSERT INTO acme_cache (key, data) 
		VALUES ($1, $2)
		ON CONFLICT (key) 
		DO UPDATE SET data = EXCLUDED.data;
	`
	_, err := p.pool.Exec(ctx, query, key, data)
	if err != nil {
		slog.Error("UPSERT query collapsed inside ACME cache commit phase", "key", key, "error", err)
		return fmt.Errorf("pgx acme cache put failed: %w", err)
	}
	return nil
}

// Delete безвозвратно удаляет закэшированный сертификат по его имени (инвалидация ключей).
func (p *PostgresCache) Delete(ctx context.Context, key string) error {
	slog.Warn("Evicting and purging Let's Encrypt TLS certificate entry from PostgreSQL cache", "key", key)
	query := `DELETE FROM acme_cache WHERE key = $1`

	_, err := p.pool.Exec(ctx, query, key)
	if err != nil {
		slog.Error("DELETE query crashed inside ACME cache eviction phase", "key", key, "error", err)
		return fmt.Errorf("pgx acme cache delete failed: %w", err)
	}
	return nil
}
