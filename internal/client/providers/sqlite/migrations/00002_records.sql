-- +goose Up
-- +goose StatementBegin

-- Создание таблицы пользовательских запечатанных секретов.
-- Реализует каноническую ссылочную целостность и доменную валидацию типов записей.
CREATE TABLE records (
    -- Уникальный детерминированный UUID v5 записи, генерируемый на базе её имени
    id TEXT PRIMARY KEY CHECK (length(trim(id)) == 36),

    -- Привязка к владельцу контейнера. Автоматически обновляется при миграциях Reconcile
    user_id TEXT REFERENCES device_state(user_id) ON UPDATE CASCADE,

    -- Открытое уникальное имя записи для индексации и поиска
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),

    -- Жестко ограниченный тип хранимого секрета ( credentials, text, binary, card )
    type TEXT NOT NULL CHECK (type IN ('credentials', 'text', 'binary', 'card')),
    
    -- Бинарный сериализованный JSON-блок crypto.Envelope (шифртекст + nonce + Poly1305 tag)
    envelope BLOB NOT NULL CHECK (length(envelope) > 0),
    
    -- Временные метки модификации записей по стандарту UTC ISO8601
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0)
);

-- Создание индекса для обеспечения мгновенного поиска по текстовому имени записи.
-- OpenSSH селекторы Cobra-команд 'get' и 'delete' опираются на этот индекс.
CREATE INDEX idx_records_name ON records(name);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_records_name;
DROP TABLE IF EXISTS records;
-- +goose StatementEnd
