-- +goose Up
-- +goose StatementBegin

-- Создание таблицы глобального состояния синглтон-контейнера устройства.
-- Ограничение CHECK (id = 1) намертво гарантирует существование строго одной записи в БД.
CREATE TABLE device_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),

    -- Сетевая привязка устройства (NULL до фазы сетевой регистрации)
    server_url TEXT CHECK (server_url IS NULL OR length(trim(server_url)) > 0),
    user_id TEXT UNIQUE CHECK (user_id IS NULL OR length(trim(user_id)) > 0), -- ДОБАВЛЕНО UNIQUE ДЛЯ ССЫЛОЧНОЙ ЦЕЛОСТНОСТИ
    
    -- Уникальный вечный UUID локального контейнера
    device_id TEXT NOT NULL CHECK (length(trim(device_id)) == 36),

    -- Бинарный блоб публичного ключа OpenSSH, выступающего корнем доверия
    ssh_public_key BLOB NOT NULL CHECK (length(ssh_public_key) > 0),

    -- Криптографическая соль аккаунта (строго 32 байта)
    account_salt BLOB NOT NULL CHECK (length(account_salt) == 32),

    -- Запечатанные крипто-конверты XChaCha20-Poly1305
    device_master_key_envelope BLOB NOT NULL CHECK (length(device_master_key_envelope) > 0),
    account_bootstrap_envelope BLOB NOT NULL CHECK (length(account_bootstrap_envelope) > 0),
    
    -- Сетевой mTLS паспорт устройства (NULL до фазы сетевой регистрации)
    encrypted_mtls_private_key BLOB CHECK (encrypted_mtls_private_key IS NULL OR length(encrypted_mtls_private_key) > 0),
    client_certificate BLOB CHECK (client_certificate IS NULL OR length(client_certificate) > 0),

    -- Системная метка времени создания контейнера в формате UTC ISO8601
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS device_state;
-- +goose StatementEnd
