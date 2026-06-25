// Package security инкапсулирует криптографическое ядро, алгоритмы деривации,
// контекстной защиты AAD и сериализации протоколов GophKeeper.
package security

import (
	"context"
	"encoding/binary"
	"log/slog"
	"strings"
)

const (
	// Version1 определяет фиксированную версию сериализации согласно спецификации.
	Version1 uint32 = 1

	// ContextAccountUnlock определяет текстовый домен для ключа разблокировки аккаунта.
	// Защищает от атак подмены контекста подписи (Cross-Protocol Signature Substitution).
	ContextAccountUnlock = "gophkeeper-account-unlock-v1"

	// Локальное ИБ-ограничение длины поля для безопасного кастинга в uint16 (64 КБ).
	maxDerivationFieldLength = 65535
)

// DerivationPayload отвечает за сборку и строгую Big-Endian сериализацию
// стабильного контекста деривации корневого мастер-ключа аккаунта.
type DerivationPayload struct {
	SshFingerprint string
}

// NewDerivationPayload конструирует payload на основе SHA256-фингерпринта OpenSSH ключа.
func NewDerivationPayload(fingerprint string) *DerivationPayload {
	return &DerivationPayload{
		SshFingerprint: strings.TrimSpace(fingerprint),
	}
}

// Marshal сериализует payload в стабильный Big-Endian формат для передачи в ssh-agent.
// Спецификация формата:
// version (4B) + context_len (2B) + context + fingerprint_len (2B) + fingerprint
//
// В случае обнаружения аномального превышения длин полей возвращает nil, предотвращая паники.
func (p *DerivationPayload) Marshal() []byte {
	ctxBytes := []byte(ContextAccountUnlock)
	fpBytes := []byte(p.SshFingerprint)

	// Жесткий ИБ-контроль длин полей перед аллокацией буфера для исключения integer overflow
	if len(ctxBytes) > maxDerivationFieldLength || len(fpBytes) > maxDerivationFieldLength {
		slog.ErrorContext(context.Background(), "Critical serialization anomaly: derivation payload field constraint violated")
		return nil
	}

	size := 4 + 2 + len(ctxBytes) + 2 + len(fpBytes)
	buf := make([]byte, size)

	// version (4B)
	binary.BigEndian.PutUint32(buf[0:4], Version1)

	// context
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(ctxBytes)))
	copy(buf[6:6+len(ctxBytes)], ctxBytes)

	// fingerprint
	offset := 6 + len(ctxBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(fpBytes)))
	copy(buf[offset+2:], fpBytes)

	return buf
}
