-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,                         -- UUID записи, генерируется клиентом
    user_id TEXT,                                -- ID пользователя (NULL, если оффлайн)
    name TEXT NOT NULL,                          -- Открытое имя записи для поиска/списка
    type TEXT NOT NULL,                          -- Тип записи (credentials, binary, text)
    
    envelope BLOB NOT NULL,                      -- JSON crypto.Envelope (зашифрованный payload)
    
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Создаем индекс для быстрого поиска по имени/типу
CREATE INDEX IF NOT EXISTS idx_records_name ON records(name);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS records;
-- +goose StatementEnd
