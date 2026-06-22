-- +goose Up
-- +goose StatementBegin

-- Основная таблица актуальных версий секретов
CREATE TABLE IF NOT EXISTS records (
    id UUID PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(64) NOT NULL,
    envelope BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_records_user_id ON records(user_id);

-- Таблица истории изменений (Для аудита и восстановления)
CREATE TABLE IF NOT EXISTS records_history (
    history_id BIGSERIAL PRIMARY KEY,
    record_id UUID NOT NULL,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(64) NOT NULL,
    envelope BYTEA NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    archived_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_history_record_id ON records_history(record_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS records_history;
DROP TABLE IF EXISTS records;
-- +goose StatementEnd
