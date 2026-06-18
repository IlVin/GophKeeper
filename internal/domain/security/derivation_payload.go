package security

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

const (
	DerivationPayloadVersion = 1
	DerivationPayloadContext = "gophkeeper-account-unlock-v1"

	maxEncodedFieldLen = 65535
)

var (
	ErrEmptyUserID              = errors.New("user id is empty")
	ErrInvalidUserID            = errors.New("user id is not a valid uuid")
	ErrEmptySSHFingerprint      = errors.New("ssh fingerprint is empty")
	ErrEncodedFieldTooLong      = errors.New("encoded field is too long")
	ErrInvalidDerivationVersion = errors.New("invalid derivation payload version")
)

type DerivationPayload struct {
	Version        uint32
	Context        string
	UserID         [16]byte
	SSHFingerprint []byte
}

func NewDerivationPayload(userID string, sshFingerprint []byte) (DerivationPayload, error) {
	if userID == "" {
		return DerivationPayload{}, ErrEmptyUserID
	}

	parsedUserID, err := uuid.Parse(userID)
	if err != nil {
		return DerivationPayload{}, fmt.Errorf("%w: %v", ErrInvalidUserID, err)
	}

	if len(sshFingerprint) == 0 {
		return DerivationPayload{}, ErrEmptySSHFingerprint
	}

	fp := make([]byte, len(sshFingerprint))
	copy(fp, sshFingerprint)

	return DerivationPayload{
		Version:        DerivationPayloadVersion,
		Context:        DerivationPayloadContext,
		UserID:         parsedUserID,
		SSHFingerprint: fp,
	}, nil
}

func MarshalDerivationPayload(userID string, sshFingerprint []byte) ([]byte, error) {
	payload, err := NewDerivationPayload(userID, sshFingerprint)
	if err != nil {
		return nil, err
	}

	return payload.MarshalBinary()
}

func (p DerivationPayload) MarshalBinary() ([]byte, error) {
	if p.Version != DerivationPayloadVersion {
		return nil, fmt.Errorf("%w: got=%d want=%d", ErrInvalidDerivationVersion, p.Version, DerivationPayloadVersion)
	}

	if p.UserID == [16]byte{} {
		return nil, ErrEmptyUserID
	}

	if len(p.SSHFingerprint) == 0 {
		return nil, ErrEmptySSHFingerprint
	}

	var buf bytes.Buffer

	// 1. Версия: 4 байта BigEndian
	if err := binary.Write(&buf, binary.BigEndian, p.Version); err != nil {
		return nil, fmt.Errorf("encode derivation payload version: %w", err)
	}

	// 2. Контекст: uint16 длина + байты строки
	if err := writeBinaryBytes(&buf, []byte(p.Context)); err != nil {
		return nil, fmt.Errorf("encode derivation payload context: %w", err)
	}

	// ИСПРАВЛЕНО: Пишем 16 байт UUID напрямую БЕЗ префикса длины, строго по спецификации
	if _, err := buf.Write(p.UserID[:]); err != nil {
		return nil, fmt.Errorf("encode derivation payload user id: %w", err)
	}

	// 4. Фингерпринт: uint16 длина + байты
	if err := writeBinaryBytes(&buf, p.SSHFingerprint); err != nil {
		return nil, fmt.Errorf("encode derivation payload ssh fingerprint: %w", err)
	}

	return buf.Bytes(), nil
}

func writeBinaryBytes(buf *bytes.Buffer, data []byte) error {
	if len(data) > maxEncodedFieldLen {
		return fmt.Errorf("%w: len=%d max=%d", ErrEncodedFieldTooLong, len(data), maxEncodedFieldLen)
	}

	if err := binary.Write(buf, binary.BigEndian, uint16(len(data))); err != nil {
		return fmt.Errorf("write field length: %w", err)
	}

	if _, err := buf.Write(data); err != nil {
		return fmt.Errorf("write field bytes: %w", err)
	}

	return nil
}
