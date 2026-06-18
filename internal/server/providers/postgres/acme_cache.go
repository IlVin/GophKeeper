package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/acme/autocert"
)

// pgxPoolIface объявляет только те методы пула, которые реально использует кэш.
// Тип pgxmock.PgxPoolIface автоматически удовлетворяет этому интерфейсу.
type pgxPoolIface interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

type PostgresCache struct {
	pool pgxPoolIface
}

func NewPostgresCache(pool pgxPoolIface) *PostgresCache {
	return &PostgresCache{pool: pool}
}

func (p *PostgresCache) Get(ctx context.Context, key string) ([]byte, error) {
	query := `SELECT data FROM acme_cache WHERE key = $1`
	var data []byte

	err := p.pool.QueryRow(ctx, query, key).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, fmt.Errorf("pgx acme cache get: %w", err)
	}

	return data, nil
}

func (p *PostgresCache) Put(ctx context.Context, key string, data []byte) error {
	query := `
		INSERT INTO acme_cache (key, data, updated_at) 
		VALUES ($1, $2, CURRENT_TIMESTAMP)
		ON CONFLICT (key) 
		DO UPDATE SET data = EXCLUDED.data, updated_at = CURRENT_TIMESTAMP
	`
	_, err := p.pool.Exec(ctx, query, key, data)
	if err != nil {
		return fmt.Errorf("pgx acme cache put: %w", err)
	}
	return nil
}

func (p *PostgresCache) Delete(ctx context.Context, key string) error {
	query := `DELETE FROM acme_cache WHERE key = $1`
	_, err := p.pool.Exec(ctx, query, key)
	if err != nil {
		return fmt.Errorf("pgx acme cache delete: %w", err)
	}
	return nil
}
