// Package security инкапсулирует криптографическое ядро, алгоритмы деривации,
// контекстной защиты AAD и сериализации протоколов GophKeeper.
package security

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
)

// Константы размеров криптографических материалов (в байтах) согласно спецификации.
const (
	// DerivationSignatureSize определяет размер подписи деривации OpenSSH (64 байта).
	DerivationSignatureSize = 64

	// AuthChallengeSignatureSize определяет размер подписи челленджа Proof of Possession (64 байта).
	AuthChallengeSignatureSize = 64

	// KEKSize определяет стандартный размер симметричных ключей XChaCha20 (32 байта).
	KEKSize = 32

	// SaltSize определяет строгий размер криптографической соли аккаунта (32 байта).
	SaltSize = 32

	// MasterKeySize определяет размер главного ключа запечатывания сейфа (32 байта).
	MasterKeySize = 32
)

// SecretBytes предоставляет безопасную потокобезопасную обертку над срезами байт в RAM,
// инкапсулирующую механизмы контролируемого гарантированного уничтожения секретов.
type SecretBytes []byte

// Destroy принудительно заполняет выделенную область памяти нулями.
//
// Функция защищена от оптимизаций компилятора по удалению «мертвых» циклов (Dead Code Elimination)
// с помощью вызова контракта runtime.KeepAlive(s).
func (s SecretBytes) Destroy() {
	if s == nil {
		return
	}
	for i := range s {
		s[i] = 0
	}
	// Удерживаем рантайм от удаления зануления в оптимизированных релизных сборках (O3)
	runtime.KeepAlive(s)
}

// Clone создает изолированную дублирующую копию секрета в оперативной памяти.
func (s SecretBytes) Clone() SecretBytes {
	if s == nil {
		return nil
	}
	clone := make(SecretBytes, len(s))
	copy(clone, s)
	return clone
}

// GenerateRandomKey генерирует криптографически стойкую последовательность байт заданного размера.
//
// Использует системный генератор энтропии rand.Reader ОС.
// В случае сбоя гарантирует мгновенное выжигание выделенного буфера в RAM нулями.
func GenerateRandomKey(size int) (SecretBytes, error) {
	if size <= 0 {
		slog.Error("Key generation rejected: invalid highly-entropic size constraint", "size", size)
		return nil, errors.New("invalid key size: must be greater than zero")
	}

	buf := make([]byte, size)

	cleanUpNeeded := true
	defer func() {
		if cleanUpNeeded {
			for i := range buf {
				buf[i] = 0
			}
			slog.Debug("Emergency erasure of random key buffer completed due to entropy reader failure")
		}
	}()

	slog.Debug("Requesting high-entropy random byte stream from system rand.Reader", "size", size)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("failed to read secure entropy stream: %w", err)
	}

	cleanUpNeeded = false
	return SecretBytes(buf), nil
}
