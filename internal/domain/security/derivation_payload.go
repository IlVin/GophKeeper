package security

import (
	"encoding/binary"
	"strings"
)

const (
	// Version1 определяет фиксированную версию сериализации согласно спеке
	Version1 uint32 = 1
	// ContextAccountUnlock определяет текстовый домен для ключа разблокировки
	ContextAccountUnlock = "gophkeeper-account-unlock-v1"
)

// DerivationPayload отвечает за сборку стабильного контекста деривации
type DerivationPayload struct {
	SshFingerprint string
}

// NewDerivationPayload конструирует payload на основе SHA256-фингерпринта ключа
func NewDerivationPayload(fingerprint string) *DerivationPayload {
	return &DerivationPayload{
		SshFingerprint: strings.TrimSpace(fingerprint),
	}
}

// Marshal сериализует payload в стабильный Big-Endian формат:
// version (4B) + context_len (2B) + context + fingerprint_len (2B) + fingerprint
func (p *DerivationPayload) Marshal() []byte {
	ctxBytes := []byte(ContextAccountUnlock)
	fpBytes := []byte(p.SshFingerprint)

	size := 4 + 2 + len(ctxBytes) + 2 + len(fpBytes)
	buf := make([]byte, size)

	binary.BigEndian.PutUint32(buf[0:4], Version1)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(ctxBytes)))
	copy(buf[6:6+len(ctxBytes)], ctxBytes)

	offset := 6 + len(ctxBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(fpBytes)))
	copy(buf[offset+2:], fpBytes)

	return buf
}
