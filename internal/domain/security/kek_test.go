package security_test

import (
	"testing"

	"gophkeeper/internal/domain/security"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeriveAccountUnlockKey_Success_And_SaltLengthEnforcement проверяет успешную
// деривацию HKDF-SHA256 ключа разблокировки и жесткий барьер на 32-байтную соль.
func TestDeriveAccountUnlockKey_Success_And_SaltLengthEnforcement(t *testing.T) {
	mockSignature := make([]byte, 64)
	for i := range mockSignature {
		mockSignature[i] = byte(i)
	}

	// 1. Тест-барьер: передача невалидной соли (размер меньше 32 байт) должна вызывать ошибку
	invalidSalt := []byte{0x01, 0x02}
	key, err := security.DeriveAccountUnlockKey(mockSignature, invalidSalt)
	assert.ErrorIs(t, err, security.ErrInvalidSalt)
	assert.Nil(t, key)

	// 2. Успешный сценарий: передача честной 32-байтной соли
	validSalt := make([]byte, 32)
	for i := range validSalt {
		validSalt[i] = byte(i + 10)
	}

	unlockKey, err := security.DeriveAccountUnlockKey(mockSignature, validSalt)
	require.NoError(t, err, "Вывод ключа разблокировки на верных размерах должен пройти успешно")
	require.Len(t, unlockKey, 32, "Размер выведенного симметричного ключа должен составлять ровно 32 байта")

	defer unlockKey.Destroy()
}

// TestDeriveDeviceKEK_Success проверяет успешный вывод DeviceKEK на базе AccountUnlockKey.
func TestDeriveDeviceKEK_Success(t *testing.T) {
	mockUnlockKey := security.SecretBytes(make([]byte, 32))
	for i := range mockUnlockKey {
		mockUnlockKey[i] = byte(i)
	}
	defer mockUnlockKey.Destroy()

	deviceID := []byte("a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d")

	deviceKEK, err := security.DeriveDeviceKEK(mockUnlockKey, deviceID)
	require.NoError(t, err)
	require.Len(t, deviceKEK, 32)

	defer deviceKEK.Destroy()
}
