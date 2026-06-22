-- +goose Up
-- +goose StatementBegin

-- 1. Таблица аккаунтов пользователей (Zero-Knowledge & Passwordless Core)
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,                  -- Внутренний UserID
    ssh_fingerprint VARCHAR(255) NOT NULL UNIQUE, -- Уникальный хэш SHA256 Ed25519 ключа
    ssh_public_key BYTEA NOT NULL,               -- Полный публичный ключ OpenSSH Wire BLOB
    
    -- Каноническое состояние аккаунта (Инвариант №11)
    canonical_account_salt BYTEA NOT NULL,       -- 32 байта соли аккаунта, присланные клиентом
    canonical_bootstrap_envelope BYTEA NOT NULL, -- Облачный конверт мастер-ключа под AccountUnlockKey
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Индекс для мгновенного поиска аккаунта по фингерпринту при RegisterBegin/AttachBegin
CREATE INDEX IF NOT EXISTS idx_users_ssh_fingerprint ON users(ssh_fingerprint);


-- 2. Таблица зарегистрированных контейнеров/устройств (Device Registry & mTLS)
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY,                          -- DeviceID локального контейнера SQLite
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    device_master_key_envelope BYTEA NOT NULL,   -- Непрозрачный клиентский конверт под DeviceKEK
    client_certificate BYTEA NOT NULL,           -- Полный выданный mTLS сертификат устройства
    cert_serial_number NUMERIC NOT NULL UNIQUE,  -- Уникальный серийный номер для запрета reuse (mTLS инвариант)
    
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- active | revoked
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_sync_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);


-- 3. Таблица одноразовых сессий челленджа (Challenge State Machine)
CREATE TABLE IF NOT EXISTS challenge_sessions (
    id UUID PRIMARY KEY,                          -- SessionID челленджа
    user_id VARCHAR(255) NOT NULL,                        -- Целевой UserID (новый или существующий)
    server_nonce BYTEA NOT NULL,                  -- Случайный 32-байтный одноразовый нонс сервера
    operation VARCHAR(64) NOT NULL,               -- register | attach-device
    
    -- Автомат состояний: Unused | Authenticated | Used | Completed | Expired
    state VARCHAR(32) NOT NULL DEFAULT 'Unused',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL  -- Строго CreatedAt + 5 минут
);

-- Индекс для очистки устаревших сессий по TTL и быстрой проверки при Finish фазах
CREATE INDEX IF NOT EXISTS idx_challenge_sessions_lookup ON challenge_sessions(id, state, expires_at);


-- 4. Таблица логирования системных событий (Device Audit Log)
CREATE TABLE IF NOT EXISTS audit_device_events (
    event_id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(255),
    device_id UUID,
    action VARCHAR(255) NOT NULL,                -- register_attempt | register_success | device_revoked
    operator_ip VARCHAR(64) NOT NULL
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_device_events;
DROP TABLE IF EXISTS challenge_sessions;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
