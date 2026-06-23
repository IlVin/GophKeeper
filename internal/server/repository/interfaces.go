// Package repository предоставляет абстрактные интерфейсы и доменные структуры
// данных для взаимодействия со слоем персистентного хранения сервера GophKeeper.
package repository

import (
	"context"
	"math/big"
	"time"
)

// User представляет доменную модель аккаунта пользователя на сервере.
// Инкапсулирует криптографическую личность и каноническое состояние солей.
type User struct {
	ID                         string // Внутренний UserID аккаунта
	SshFingerprint             string // SHA256 фингерпринт OpenSSH ключа
	SshPublicKey               []byte // Полный публичный ключ OpenSSH Wire BLOB
	CanonicalAccountSalt       []byte // 32 байта канонической соли аккаунта
	CanonicalBootstrapEnvelope []byte // Канонический облачный конверт мастер-ключа
	CreatedAt                  time.Time
}

// Destroy выполняет превентивное затирание конфиденциальных байтовых массивов в памяти.
func (u *User) Destroy() {
	if u == nil {
		return
	}
	for i := range u.CanonicalAccountSalt {
		u.CanonicalAccountSalt[i] = 0
	}
	u.SshPublicKey = nil
	u.CanonicalBootstrapEnvelope = nil
}

// Device представляет модель зарегистрированного клиентского контейнера.
type Device struct {
	ID                      string   // UUID устройства, сгенерированный при init
	UserID                  string   // Ссылка на UserID владельца аккаунта
	DeviceMasterKeyEnvelope []byte   // Локальный конверт мастер-ключа устройства
	ClientCertificate       []byte   // Выпущенный x509 DER mTLS сертификат
	CertSerialNumber        *big.Int // Уникальный серийный номер сертификата
	Status                  string   // active | revoked
	RegisteredAt            time.Time
	LastSyncAt              time.Time
}

// ChallengeSession описывает сессию одноразового криптографического челленджа.
type ChallengeSession struct {
	ID          string // SessionID сессии
	UserID      string // Ссылка на целевой UserID
	ServerNonce []byte // 32-байтный случайный нонс сервера для защиты от Replay
	Operation   string // register | attach-device
	State       string // Unused | Authenticated | Used | Completed | Expired
	CreatedAt   time.Time
	ExpiresAt   time.Time // Срок жизни сессии (строго CreatedAt + 5 минут)
}

// Destroy выполняет принудительное выжигание одноразового серверного нонса.
func (c *ChallengeSession) Destroy() {
	if c == nil {
		return
	}
	for i := range c.ServerNonce {
		c.ServerNonce[i] = 0
	}
	c.ServerNonce = nil
}

// UserRepository определяет контракт долгосрочного управления аккаунтами.
type UserRepository interface {
	CreateUser(ctx context.Context, user *User) error
	GetByFingerprint(ctx context.Context, fingerprint string) (*User, error)
}

// DeviceRepository определяет контракт ведения реестра mTLS-паспортов контейнеров.
type DeviceRepository interface {
	CreateDevice(ctx context.Context, device *Device) error
	GetByID(ctx context.Context, id string) (*Device, error)
	UpdateSyncTime(ctx context.Context, id string) error
	UpdateStatus(ctx context.Context, id string, status string) error
}

// ChallengeRepository координирует транзакции конечного автомата сессий челленджей.
type ChallengeRepository interface {
	CreateChallengeSession(ctx context.Context, session *ChallengeSession) error

	// ConsumeChallengeSession атомарно внутри честной ACID-транзакции СУБД извлекает сессию,
	// верифицирует статус 'Unused' и мгновенно переводит её в состояние 'Used'.
	// Полностью ликвидирует возможность конкурентных Replay-атак (Double Spending) обхода mTLS.
	ConsumeChallengeSession(ctx context.Context, id string) (*ChallengeSession, error)

	UpdateState(ctx context.Context, id string, newState string) error
}
