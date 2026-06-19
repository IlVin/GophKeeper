package security

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"
)

const (
	DerivationSignatureSize    = 64
	AuthChallengeSignatureSize = 64
	KEKSize                    = 32
	SaltSize                   = 32
	DeviceIDSize               = 16
	MasterKeySize              = 32
)

type DerivationSignature [DerivationSignatureSize]byte
type AccountUnlockKey [KEKSize]byte
type DeviceKEK [KEKSize]byte
type AccountSalt [SaltSize]byte
type DeviceID [DeviceIDSize]byte

type AccountMasterKey [MasterKeySize]byte
type AuthChallengeSignature [AuthChallengeSignatureSize]byte
type SSHPublicKey []byte
type SSHFingerprint string

func NewDerivationSignature(raw []byte) (DerivationSignature, error) {
	if len(raw) != DerivationSignatureSize {
		return DerivationSignature{}, fmt.Errorf("invalid derivation signature length: got=%d want=%d", len(raw), DerivationSignatureSize)
	}

	var sig DerivationSignature
	copy(sig[:], raw)

	return sig, nil
}

func (DeviceID) IsDeviceID() {}

// SecretBytes предоставляет безопасную обертку над срезами байт в RAM
type SecretBytes []byte

// Destroy заполняет память нулями и предотвращает оптимизации компилятора по удалению цикла
func (s SecretBytes) Destroy() {
	if s == nil {
		return
	}
	for i := range s {
		s[i] = 0
	}
	// Удерживаем рантайм от удаления очистки памяти в оптимизированных билдах
	runtime.KeepAlive(s)
}

// Clone создает изолированную копию секрета в памяти
func (s SecretBytes) Clone() SecretBytes {
	if s == nil {
		return nil
	}
	clone := make(SecretBytes, len(s))
	copy(clone, s)
	return clone
}

// GenerateRandomKey генерирует криптографически стойкую последовательность байт заданного размера
func GenerateRandomKey(size int) (SecretBytes, error) {
	if size <= 0 {
		return nil, errors.New("invalid key size")
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return SecretBytes(buf), nil
}
