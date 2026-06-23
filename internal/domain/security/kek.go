// Package security инкапсулирует криптографическое ядро, алгоритмы деривации,
// контекстной защиты AAD и сериализации протоколов GophKeeper.
package security

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"golang.org/x/crypto/hkdf"
)

const (
	// ContextDeviceKEK определяет текстовый маркер контекста деривации ключа KEK устройства.
	ContextDeviceKEK = "gophkeeper-device-kek-v1"
)

var (
	// ErrInvalidKeySize возвращается, если размер мастер-ключа отличен от 32 байт.
	ErrInvalidKeySize = errors.New("key material size must be exactly 32 bytes")

	// ErrInvalidSalt возвращается, если размер криптографической соли отличен от 32 байт.
	ErrInvalidSalt = errors.New("account salt must be exactly 32 bytes long")

	// ErrInvalidDevice возвращается, если передан пустой строковый идентификатор устройства.
	ErrInvalidDevice = errors.New("device id raw material cannot be empty")
)

// DeriveAccountUnlockKey вычисляет AccountUnlockKey = HKDF_SHA256(signature, salt, info, 32).
//
// Использует стабильную подпись из ssh-agent и 32-байтную соль аккаунта.
// В случае сбоя гарантирует мгновенное выжигание аллоцированной памяти нулями.
func DeriveAccountUnlockKey(rawSignature64 []byte, salt []byte) (SecretBytes, error) {
	if len(rawSignature64) != 64 {
		return nil, fmt.Errorf("invalid ed25519 signature size: got %d bytes, expected 64", len(rawSignature64))
	}
	// Усилен контроль длины соли (строго 32 байта для защиты энтропии)
	if len(salt) != 32 {
		return nil, ErrInvalidSalt
	}

	slog.Debug("Executing HKDF-SHA256 extraction for AccountUnlockKey generation")
	unlockKey := make([]byte, 32)

	cleanUpNeeded := true
	defer func() {
		if cleanUpNeeded {
			for i := range unlockKey {
				unlockKey[i] = 0
			}
			slog.Debug("Emergency erasure of unlockKey buffer executed due to derivation failure")
		}
	}()

	hkdfReader := hkdf.New(sha256.New, rawSignature64, salt, []byte(ContextAccountUnlock))
	if _, err := io.ReadFull(hkdfReader, unlockKey); err != nil {
		return nil, fmt.Errorf("hkdf expand failed for account unlock key: %w", err)
	}

	cleanUpNeeded = false
	return SecretBytes(unlockKey), nil
}

// DeriveDeviceKEK вычисляет DeviceKEK = HKDF_SHA256(AccountUnlockKey, DeviceID, info, 32).
//
// Связывает воедино ключ разблокировки аккаунта и вечный UUID локального контейнера.
func DeriveDeviceKEK(accountUnlockKey SecretBytes, rawDeviceID []byte) (SecretBytes, error) {
	if len(accountUnlockKey) != 32 {
		return nil, ErrInvalidKeySize
	}
	if len(rawDeviceID) == 0 {
		return nil, ErrInvalidDevice
	}

	slog.Debug("Executing HKDF-SHA256 extraction for DeviceKEK generation")
	deviceKek := make([]byte, 32)

	cleanUpNeeded := true
	defer func() {
		if cleanUpNeeded {
			for i := range deviceKek {
				deviceKek[i] = 0
			}
			slog.Debug("Emergency erasure of deviceKek buffer executed due to derivation failure")
		}
	}()

	hkdfReader := hkdf.New(sha256.New, accountUnlockKey, rawDeviceID, []byte(ContextDeviceKEK))
	if _, err := io.ReadFull(hkdfReader, deviceKek); err != nil {
		return nil, fmt.Errorf("hkdf expand failed for device kek: %w", err)
	}

	cleanUpNeeded = false
	return SecretBytes(deviceKek), nil
}
