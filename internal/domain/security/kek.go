package security

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	ContextDeviceKEK = "gophkeeper-device-kek-v1"
)

var (
	ErrInvalidKeySize = errors.New("key material size must be exactly 32 bytes")
	ErrInvalidSalt    = errors.New("account salt cannot be empty")
	ErrInvalidDevice  = errors.New("device id raw material cannot be empty")
)

// DeriveAccountUnlockKey вычисляет AccountUnlockKey = HKDF_SHA256(signature, salt, info, 32)
func DeriveAccountUnlockKey(rawSignature64 []byte, salt []byte) (SecretBytes, error) {
	if len(rawSignature64) != 64 {
		return nil, fmt.Errorf("invalid ed25519 signature size: got %d bytes, want 64", len(rawSignature64))
	}
	if len(salt) == 0 {
		return nil, ErrInvalidSalt
	}

	unlockKey := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, rawSignature64, salt, []byte(ContextAccountUnlock))
	if _, err := io.ReadFull(hkdfReader, unlockKey); err != nil {
		return nil, fmt.Errorf("hkdf derive unlock key failed: %w", err)
	}

	return SecretBytes(unlockKey), nil
}

// DeriveDeviceKEK вычисляет DeviceKEK = HKDF_SHA256(AccountUnlockKey, DeviceID, info, 32)
func DeriveDeviceKEK(accountUnlockKey SecretBytes, rawDeviceID16 []byte) (SecretBytes, error) {
	if len(accountUnlockKey) != 32 {
		return nil, ErrInvalidKeySize
	}
	if len(rawDeviceID16) == 0 {
		return nil, ErrInvalidDevice
	}

	deviceKek := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, accountUnlockKey, rawDeviceID16, []byte(ContextDeviceKEK))
	if _, err := io.ReadFull(hkdfReader, deviceKek); err != nil {
		return nil, fmt.Errorf("hkdf derive device kek failed: %w", err)
	}

	return SecretBytes(deviceKek), nil
}
