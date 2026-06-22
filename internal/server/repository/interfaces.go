package repository

import (
	"context"
	"math/big"
	"time"
)

// User представляет модель аккаунта на сервере
type User struct {
	ID                         string // UUID аккаунта
	SshFingerprint             string // SHA256 фингерпринт
	SshPublicKey               []byte // OpenSSH Wire BLOB
	CanonicalAccountSalt       []byte // 32 байта канонической соли
	CanonicalBootstrapEnvelope []byte // Канонический облачный конверт
	CreatedAt                  time.Time
}

// Device представляет зарегистрированный контейнер SQLite
type Device struct {
	ID                      string // UUID устройства
	UserID                  string // Ссылка на аккаунт
	DeviceMasterKeyEnvelope []byte
	ClientCertificate       []byte   // Выданный mTLS сертификат
	CertSerialNumber        *big.Int // Серийный номер сертификата для защиты от replay
	Status                  string   // active | revoked
	RegisteredAt            time.Time
	LastSyncAt              time.Time
}

// ChallengeSession описывает сессию одноразового челленджа
type ChallengeSession struct {
	ID          string // SessionID
	UserID      string
	ServerNonce []byte // 32-байтный случайный нонс сервера
	Operation   string // register | attach-device
	State       string // Unused | Authenticated | Used | Completed | Expired
	CreatedAt   time.Time
	ExpiresAt   time.Time // CreatedAt + 5 минут
}

type UserRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetByFingerprint(ctx context.Context, fingerprint string) (*User, error)
}

type DeviceRepository interface {
	CreateDevice(ctx context.Context, device *Device) error
	GetByID(ctx context.Context, id string) (*Device, error)
	UpdateSyncTime(ctx context.Context, id string) error
	UpdateStatus(ctx context.Context, id string, status string) error
}

type ChallengeRepository interface {
	CreateChallengeSession(ctx context.Context, session *ChallengeSession) error
	GetAndLock(ctx context.Context, id string) (*ChallengeSession, error)
	UpdateState(ctx context.Context, id string, newState string) error
}
