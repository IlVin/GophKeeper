-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS acme_cache (
    key TEXT PRIMARY KEY,
    data BYTEA NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS acme_cache;
-- +goose StatementEnd
