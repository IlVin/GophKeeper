package security

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustDeviceIDFromUUID(t *testing.T, s string) DeviceID {
	t.Helper()

	u := uuid.MustParse(s)
	var id DeviceID
	copy(id[:], u[:])

	return id
}

func TestDeriveAccountUnlockKey(t *testing.T) {
	t.Parallel()

	makeSignature := func(s string) DerivationSignature {
		var sig DerivationSignature
		copy(sig[:], []byte(s))
		return sig
	}

	makeSalt := func(s string) AccountSalt {
		var salt AccountSalt
		copy(salt[:], []byte(s))
		return salt
	}

	signature := makeSignature("1234567890123456789012345678901234567890123456789012345678901234")
	salt := makeSalt("abcdefghijklmnopqrstuvwxzy123456")

	got, err := DeriveAccountUnlockKey(signature, salt)
	require.NoError(t, err)
	assert.Len(t, got, KEKSize)
}

func TestDeriveDeviceKEK(t *testing.T) {
	t.Parallel()

	makeAccountUnlockKey := func(s string) AccountUnlockKey {
		var key AccountUnlockKey
		copy(key[:], []byte(s))
		return key
	}

	accountUnlockKey := makeAccountUnlockKey("12345678901234567890123456789012")
	deviceID := mustDeviceIDFromUUID(t, "550e8400-e29b-41d4-a716-446655440000")

	got, err := DeriveDeviceKEK(accountUnlockKey, deviceID)
	require.NoError(t, err)
	assert.Len(t, got, KEKSize)
}

func TestDeriveKeys_Deterministic(t *testing.T) {
	t.Parallel()

	makeSignature := func(s string) DerivationSignature {
		var sig DerivationSignature
		copy(sig[:], []byte(s))
		return sig
	}

	makeAccountUnlockKey := func(s string) AccountUnlockKey {
		var key AccountUnlockKey
		copy(key[:], []byte(s))
		return key
	}

	makeAccountSalt := func(s string) AccountSalt {
		var salt AccountSalt
		copy(salt[:], []byte(s))
		return salt
	}

	t.Run("account unlock key deterministic", func(t *testing.T) {
		t.Parallel()

		signature := makeSignature("1234567890123456789012345678901234567890123456789012345678901234")
		salt := makeAccountSalt("abcdefghijklmnopqrstuvwxzy123456")

		got1, err := DeriveAccountUnlockKey(signature, salt)
		require.NoError(t, err)

		got2, err := DeriveAccountUnlockKey(signature, salt)
		require.NoError(t, err)

		assert.Equal(t, got1, got2)
	})

	t.Run("device kek deterministic", func(t *testing.T) {
		t.Parallel()

		accountUnlockKey := makeAccountUnlockKey("12345678901234567890123456789012")
		deviceID := mustDeviceIDFromUUID(t, "550e8400-e29b-41d4-a716-446655440000")

		got1, err := DeriveDeviceKEK(accountUnlockKey, deviceID)
		require.NoError(t, err)

		got2, err := DeriveDeviceKEK(accountUnlockKey, deviceID)
		require.NoError(t, err)

		assert.Equal(t, got1, got2)
	})
}

func TestDeriveKeys_ChangesWithInput(t *testing.T) {
	t.Parallel()

	makeSignature := func(s string) DerivationSignature {
		var sig DerivationSignature
		copy(sig[:], []byte(s))
		return sig
	}

	makeAccountUnlockKey := func(s string) AccountUnlockKey {
		var key AccountUnlockKey
		copy(key[:], []byte(s))
		return key
	}

	makeAccountSalt := func(s string) AccountSalt {
		var salt AccountSalt
		copy(salt[:], []byte(s))
		return salt
	}

	t.Run("account unlock key variations", func(t *testing.T) {
		t.Parallel()

		got1, err := DeriveAccountUnlockKey(
			makeSignature("1234567890123456789012345678901234567890123456789012345678901234"),
			makeAccountSalt("abcdefghijklmnopqrstuvwxzy123456"),
		)
		require.NoError(t, err)

		got2, err := DeriveAccountUnlockKey(
			makeSignature("1234567890123456789012345678901234567890123456789012345678901234"),
			makeAccountSalt("zyxwvutsrqponmlkjihgfedcba654321"),
		)
		require.NoError(t, err)

		got3, err := DeriveAccountUnlockKey(
			makeSignature("abcdefghijklmnopqrstuvwxzy123456abcdefghijklmnopqrstuvwxzy1234"),
			makeAccountSalt("abcdefghijklmnopqrstuvwxzy123456"),
		)
		require.NoError(t, err)

		assert.NotEqual(t, got1, got2)
		assert.NotEqual(t, got1, got3)
	})

	t.Run("device kek variations", func(t *testing.T) {
		t.Parallel()

		got1, err := DeriveDeviceKEK(
			makeAccountUnlockKey("12345678901234567890123456789012"),
			mustDeviceIDFromUUID(t, "550e8400-e29b-41d4-a716-446655440000"),
		)
		require.NoError(t, err)

		got2, err := DeriveDeviceKEK(
			makeAccountUnlockKey("12345678901234567890123456789012"),
			mustDeviceIDFromUUID(t, "550e8400-e29b-41d4-a716-446655440001"),
		)
		require.NoError(t, err)

		got3, err := DeriveDeviceKEK(
			makeAccountUnlockKey("abcdefghijklmnopqrstuvwxzy123456"),
			mustDeviceIDFromUUID(t, "550e8400-e29b-41d4-a716-446655440000"),
		)
		require.NoError(t, err)

		assert.NotEqual(t, got1, got2)
		assert.NotEqual(t, got1, got3)
	})
}

func TestDeriveKeys_DomainSeparation(t *testing.T) {
	t.Parallel()

	var signature DerivationSignature
	copy(signature[:], []byte("1234567890123456789012345678901234567890123456789012345678901234"))

	var accountSalt AccountSalt
	copy(accountSalt[:], []byte("abcdefghijklmnopqrstuvwxzy123456"))

	accountUnlockKey, err := DeriveAccountUnlockKey(signature, accountSalt)
	require.NoError(t, err)

	deviceID := mustDeviceIDFromUUID(t, "550e8400-e29b-41d4-a716-446655440000")
	deviceKEK, err := DeriveDeviceKEK(accountUnlockKey, deviceID)
	require.NoError(t, err)

	assert.NotEqual(t, accountUnlockKey[:], deviceKEK[:])
}
