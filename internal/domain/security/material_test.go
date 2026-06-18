package security

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaterial_ExactSizesAndTypes(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 64, DerivationSignatureSize)
	assert.Equal(t, 32, KEKSize)
	assert.Equal(t, 32, SaltSize)
	assert.Equal(t, 16, DeviceIDSize)

	assert.Equal(t, uintptr(DerivationSignatureSize), unsafe.Sizeof(DerivationSignature{}))
	assert.Equal(t, uintptr(KEKSize), unsafe.Sizeof(AccountUnlockKey{}))
	assert.Equal(t, uintptr(KEKSize), unsafe.Sizeof(DeviceKEK{}))
	assert.Equal(t, uintptr(SaltSize), unsafe.Sizeof(AccountSalt{}))
	assert.Equal(t, uintptr(DeviceIDSize), unsafe.Sizeof(DeviceID{}))
}

func TestNewDerivationSignature(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		raw := make([]byte, DerivationSignatureSize)
		for i := range raw {
			raw[i] = byte(i)
		}

		got, err := NewDerivationSignature(raw)
		require.NoError(t, err)
		assert.Equal(t, raw, got[:])
	})

	t.Run("invalid length", func(t *testing.T) {
		t.Parallel()

		_, err := NewDerivationSignature(make([]byte, DerivationSignatureSize-1))
		require.Error(t, err)
	})
}
