package security

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	infoAccountUnlockKey = "gophkeeper-account-unlock-v1"
	infoDeviceKEK        = "gophkeeper-device-kek-v1"
)

func DeriveAccountUnlockKey(signature DerivationSignature, accountSalt AccountSalt) (AccountUnlockKey, error) {
	reader := hkdf.New(sha256.New, signature[:], accountSalt[:], []byte(infoAccountUnlockKey))

	var key AccountUnlockKey
	if _, err := io.ReadFull(reader, key[:]); err != nil {
		return AccountUnlockKey{}, fmt.Errorf("derive account unlock key: %w", err)
	}

	return key, nil
}

func DeriveDeviceKEK(accountUnlockKey AccountUnlockKey, deviceID DeviceID) (DeviceKEK, error) {
	reader := hkdf.New(sha256.New, accountUnlockKey[:], deviceID[:], []byte(infoDeviceKEK))

	var kek DeviceKEK
	if _, err := io.ReadFull(reader, kek[:]); err != nil {
		return DeviceKEK{}, fmt.Errorf("derive device kek: %w", err)
	}

	return kek, nil
}
