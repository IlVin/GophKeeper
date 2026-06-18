package security

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDerivationPayload_Success(t *testing.T) {
	t.Parallel()

	userID := "550e8400-e29b-41d4-a716-446655440000"
	sshFingerprint := []byte{0x01, 0x02, 0x03, 0x04}
	wantUUID := [16]byte(uuid.MustParse(userID))

	got, err := NewDerivationPayload(userID, sshFingerprint)
	require.NoError(t, err)

	assert.Equal(t, uint32(DerivationPayloadVersion), got.Version)
	assert.Equal(t, DerivationPayloadContext, got.Context)
	assert.Equal(t, wantUUID, got.UserID)
	assert.Equal(t, sshFingerprint, got.SSHFingerprint)
}

func TestNewDerivationPayload_Validate(t *testing.T) {
	t.Parallel()

	validUserID := "550e8400-e29b-41d4-a716-446655440000"
	validFingerprint := []byte{0xAA, 0xBB, 0xCC}
	wantUUID := [16]byte(uuid.MustParse(validUserID))

	tests := []struct {
		name           string
		userID         string
		sshFingerprint []byte
		wantErr        error
	}{
		{
			name:           "empty user id",
			userID:         "",
			sshFingerprint: validFingerprint,
			wantErr:        ErrEmptyUserID,
		},
		{
			name:           "invalid user id",
			userID:         "user-123",
			sshFingerprint: validFingerprint,
			wantErr:        ErrInvalidUserID,
		},
		{
			name:           "empty ssh fingerprint",
			userID:         validUserID,
			sshFingerprint: nil,
			wantErr:        ErrEmptySSHFingerprint,
		},
		{
			name:           "success",
			userID:         validUserID,
			sshFingerprint: validFingerprint,
			wantErr:        nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NewDerivationPayload(tt.userID, tt.sshFingerprint)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, wantUUID, got.UserID)
			assert.Equal(t, validFingerprint, got.SSHFingerprint)
		})
	}
}

func TestNewDerivationPayload_CopiesFingerprint(t *testing.T) {
	t.Parallel()

	userID := "550e8400-e29b-41d4-a716-446655440000"
	src := []byte{0x10, 0x20, 0x30}

	got, err := NewDerivationPayload(userID, src)
	require.NoError(t, err)

	src[0] = 0xFF

	assert.Equal(t, []byte{0x10, 0x20, 0x30}, got.SSHFingerprint)
}

func TestMarshalDerivationPayload_Deterministic(t *testing.T) {
	t.Parallel()

	userID := "550e8400-e29b-41d4-a716-446655440000"
	sshFingerprint := []byte{0x01, 0x02, 0x03, 0x04}

	a, err := MarshalDerivationPayload(userID, sshFingerprint)
	require.NoError(t, err)

	b, err := MarshalDerivationPayload(userID, sshFingerprint)
	require.NoError(t, err)

	assert.Equal(t, a, b, "MarshalDerivationPayload must be strictly deterministic")
}

func TestMarshalDerivationPayload_DifferentFieldsProduceDifferentBytes(t *testing.T) {
	t.Parallel()

	user1 := "550e8400-e29b-41d4-a716-446655440000"
	user2 := "550e8400-e29b-41d4-a716-446655440001"

	base, err := MarshalDerivationPayload(user1, []byte{0x01, 0x02, 0x03})
	require.NoError(t, err)

	otherUser, err := MarshalDerivationPayload(user2, []byte{0x01, 0x02, 0x03})
	require.NoError(t, err)

	otherFingerprint, err := MarshalDerivationPayload(user1, []byte{0x09, 0x08, 0x07})
	require.NoError(t, err)

	assert.NotEqual(t, base, otherUser, "payload bytes must differ when user_id changes")
	assert.NotEqual(t, base, otherFingerprint, "payload bytes must differ when ssh_fingerprint changes")
}

func TestDerivationPayload_MarshalBinary_ExactEncoding(t *testing.T) {
	t.Parallel()

	userID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	sshFingerprint := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	got, err := MarshalDerivationPayload(userID.String(), sshFingerprint)
	require.NoError(t, err)

	var want bytes.Buffer

	err = binary.Write(&want, binary.BigEndian, uint32(DerivationPayloadVersion))
	require.NoError(t, err)

	writeWantBytes := func(data []byte) {
		t.Helper()
		err := binary.Write(&want, binary.BigEndian, uint16(len(data)))
		require.NoError(t, err)
		_, err = want.Write(data)
		require.NoError(t, err)
	}

	writeWantBytes([]byte(DerivationPayloadContext))

	// ИСПРАВЛЕНО: Пишем 16 байт UUID напрямую в эталонный буфер, без вызова префикса длины
	_, err = want.Write(userID[:])
	require.NoError(t, err)

	writeWantBytes(sshFingerprint)

	assert.Equal(t, want.Bytes(), got, "encoded payload bytes mismatch target exact specification layout")
}

func TestDerivationPayload_MarshalBinary_InvalidVersion(t *testing.T) {
	t.Parallel()

	payload := DerivationPayload{
		Version:        999,
		Context:        DerivationPayloadContext,
		UserID:         [16]byte(uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")),
		SSHFingerprint: []byte{0x01, 0x02},
	}

	_, err := payload.MarshalBinary()
	assert.ErrorIs(t, err, ErrInvalidDerivationVersion)
}

func TestDerivationPayload_MarshalBinary_EmptyUserID(t *testing.T) {
	t.Parallel()

	payload := DerivationPayload{
		Version:        DerivationPayloadVersion,
		Context:        DerivationPayloadContext,
		SSHFingerprint: []byte{0x01, 0x02},
	}

	_, err := payload.MarshalBinary()
	assert.ErrorIs(t, err, ErrEmptyUserID)
}

func TestDerivationPayload_MarshalBinary_EmptyFingerprint(t *testing.T) {
	t.Parallel()

	payload := DerivationPayload{
		Version: DerivationPayloadVersion,
		Context: DerivationPayloadContext,
		UserID:  [16]byte(uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")),
	}

	_, err := payload.MarshalBinary()
	assert.ErrorIs(t, err, ErrEmptySSHFingerprint)
}

func TestDerivationPayload_MarshalBinary_TooLongField(t *testing.T) {
	t.Parallel()

	tooLongFingerprint := make([]byte, maxEncodedFieldLen+1)

	payload := DerivationPayload{
		Version:        DerivationPayloadVersion,
		Context:        DerivationPayloadContext,
		UserID:         [16]byte(uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")),
		SSHFingerprint: tooLongFingerprint,
	}

	_, err := payload.MarshalBinary()
	assert.ErrorIs(t, err, ErrEncodedFieldTooLong)
}
