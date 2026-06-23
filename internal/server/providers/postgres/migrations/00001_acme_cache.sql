-- +goose Up
-- +goose StatementBegin

-- Таблица acme_cache обеспечивает персистентное централизованное хранение 
-- TLS-сертификатов Let's Encrypt в кластере PostgreSQL для autocert.Manager.
CREATE TABLE IF NOT EXISTS acme_cache (
    key TEXT PRIMARY KEY,
    data BYTEA NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Создаем автоматическую функцию для канонического обновления временных меток LWW
CREATE OR REPLACE FUNCTION update_acme_cache_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Навешиваем триггер для автоматической фиксации времени модификации данных
CREATE OR REPLACE TRIGGER trigger_update_acme_cache_timestamp
    BEFORE UPDATE ON acme_cache
    FOR EACH ROW
    EXECUTE FUNCTION update_acme_cache_timestamp();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trigger_update_acme_cache_timestamp ON acme_cache;
DROP FUNCTION IF EXISTS update_acme_cache_timestamp();
DROP TABLE IF EXISTS acme_cache;
-- +goose StatementEnd
