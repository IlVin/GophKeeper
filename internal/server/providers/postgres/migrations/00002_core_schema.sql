-- +goose Up
-- +goose StatementBegin

-- 1. Таблица аккаунтов пользователей (Zero-Knowledge & Passwordless Core)
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,                  -- Внутренний канонический UserID (фингерпринт)
    ssh_fingerprint VARCHAR(255) NOT NULL UNIQUE, -- Уникальный хэш SHA256 Ed25519 ключа
    ssh_public_key BYTEA NOT NULL,               -- Полный публичный ключ OpenSSH Wire BLOB
    
    -- Каноническое состояние аккаунта (Инвариант №11)
    canonical_account_salt BYTEA NOT NULL,       -- 32 байта соли аккаунта, присланные клиентом
    canonical_bootstrap_envelope BYTEA NOT NULL, -- Облачный конверт мастер-ключа под AccountUnlockKey
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_ssh_fingerprint ON users(ssh_fingerprint);


-- 2. Таблица зарегистрированных контейнеров/устройств (Device Registry & mTLS)
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY,                          -- DeviceID локального контейнера SQLite
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    device_master_key_envelope BYTEA NOT NULL,   -- Непрозрачный клиентский конверт под DeviceKEK
    client_certificate BYTEA NOT NULL,           -- Полный выданный mTLS сертификат устройства
    cert_serial_number NUMERIC NOT NULL UNIQUE,  -- Уникальный серийный номер для запрета reuse (mTLS инвариант)
    
    status VARCHAR(32) NOT NULL DEFAULT 'active', 
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_sync_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Жесткий ИБ-контроль статусов на уровне СУБД
    CONSTRAINT check_device_status CHECK (status IN ('active', 'revoked'))
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);


-- 3. Таблица одноразовых сессий челленджа (Challenge State Machine)
CREATE TABLE IF NOT EXISTS challenge_sessions (
    id UUID PRIMARY KEY,                          -- SessionID челленджа
    user_id VARCHAR(255) NOT NULL,                -- Целевой UserID (новый или существующий)
    server_nonce BYTEA NOT NULL,                  -- Случайный 32-байтный одноразовый нонс сервера
    operation VARCHAR(64) NOT NULL,               -- register | attach-device
    state VARCHAR(32) NOT NULL DEFAULT 'Unused',  -- Текущее состояние конечного автомата
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, -- Строго CreatedAt + 5 минут
    
    -- Ограничение автомата состояний сессии челленджа
    CONSTRAINT check_challenge_state CHECK (state IN ('Unused', 'Authenticated', 'Used', 'Completed', 'Expired')),
    CONSTRAINT check_challenge_operation CHECK (operation IN ('register', 'attach-device'))
);

CREATE INDEX IF NOT EXISTS idx_challenge_sessions_lookup ON challenge_sessions(id, state, expires_at);


-- 4. ИСПРАВЛЕНО: Добавлена таблица хранения актуальных зашифрованных секретов (Records Vault)
CREATE TABLE IF NOT EXISTS records (
    id UUID PRIMARY KEY,                          -- Детерминированный UUID v5 записи клиента
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,                   -- Открытое имя для локального поиска и вывода в list
    type VARCHAR(32) NOT NULL,                    -- Тип записи (credentials, binary, text, card)
    envelope BYTEA NOT NULL,                      -- Бинарный конверт Poly1305 (шифртекст + nonce + tag)
    created_at TIMESTAMP WITH TIME ZONE NOT NULL, -- Время создания, переданное клиентом
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL, -- Время модификации для LWW-сверки
    
    -- Жесткий ИБ-контроль типов секретов на стороне PostgreSQL
    CONSTRAINT check_record_type CHECK (type IN ('credentials', 'binary', 'text', 'card'))
);

CREATE INDEX IF NOT EXISTS idx_records_user_sync ON records(user_id, updated_at);


-- 5. ИСПРАВЛЕНО: Добавлена таблица ведения истории изменений секретов (History Audit Trail)
CREATE TABLE IF NOT EXISTS records_history (
    history_id BIGSERIAL PRIMARY KEY,
    record_id UUID NOT NULL,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(32) NOT NULL,
    envelope BYTEA NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    archived_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_records_history_lookup ON records_history(record_id, updated_at);


-- 6. Таблица логирования системных событий (Device Audit Log)
CREATE TABLE IF NOT EXISTS audit_device_events (
    event_id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(255),
    device_id UUID,
    action VARCHAR(255) NOT NULL,                -- register_attempt | register_success | device_revoked
    operator_ip VARCHAR(64) NOT NULL
);


-- 7. Автоматизация LWW обновлений для таблицы users
CREATE OR REPLACE FUNCTION update_users_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trigger_update_users_timestamp
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_users_timestamp();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trigger_update_users_timestamp ON users;
DROP FUNCTION IF EXISTS update_users_timestamp();

DROP TABLE IF EXISTS audit_device_events;
DROP TABLE IF EXISTS records_history;
DROP TABLE IF EXISTS records;
DROP TABLE IF EXISTS challenge_sessions;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
