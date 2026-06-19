package repository

import (
	"context"
)

// LocalDeviceState представляет структуру для записи в таблицу device_state
type LocalDeviceState struct {
	ServerURL                *string // Используем указатель для поддержки NULL
	UserID                   *string // Используем указатель для поддержки NULL
	DeviceID                 string
	SshPublicKey             []byte // Настоящие байты OpenSSH
	AccountSalt              []byte // Соль
	DeviceMasterKeyEnvelope  []byte
	AccountBootstrapEnvelope []byte
	EncryptedMtlsPrivateKey  *[]byte // Указатель для поддержки NULL
	ClientCertificate        *[]byte // Указатель для поддержки NULL
	CreatedAt                string
}

type DeviceStore interface {
	SaveDeviceState(ctx context.Context, state *LocalDeviceState) error
	ReadDeviceState(ctx context.Context) (*LocalDeviceState, error)
}
