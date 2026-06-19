-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS device_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),

    server_url TEXT,                             -- URL gRPC-сервера
    user_id TEXT,                                -- UUID пользователя
    device_id TEXT NOT NULL,                     -- UUID локального контейнера

    ssh_public_key BLOB NOT NULL,                -- OpenSSH public key blob

    account_salt BLOB NOT NULL,                  -- AccountSalt

    device_master_key_envelope BLOB NOT NULL,    -- AccountMasterKey encrypted under DeviceKEK
    account_bootstrap_envelope BLOB NOT NULL,    -- AccountMasterKey encrypted under AccountUnlockKey
    encrypted_mtls_private_key BLOB,             -- MtlsPrivateKey encrypted under DeviceKEK
    client_certificate BLOB,                     -- Issued client mTLS certificate

    created_at TEXT NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS device_state;
-- +goose StatementEnd