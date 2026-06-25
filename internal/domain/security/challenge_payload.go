// Package security инкапсулирует криптографическое ядро, алгоритмы деривации,
// контекстной защиты AAD и сериализации протоколов GophKeeper.
package security

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"strings"
)

const (
	// ContextAuthChallenge определяет уникальный контекстный маркер подписи челленджа.
	// Защищает от атак подмены типа подписи (Cross-Protocol Signature Substitution).
	ContextAuthChallenge = "gophkeeper-auth-challenge-v1"

	// Локальная константа версии протокола сериализации челленджа.
	challengeVersion1 = uint32(1)

	// Максимальная длина строкового поля для безопасного приведения к uint16 (64 КБ).
	maxFieldLength = 65535
)

var (
	// ErrFieldTooLong возвращается, если размер одного из полей превышает лимит uint16.
	ErrFieldTooLong = errors.New("challenge payload field exceeds maximum length of 65535 bytes")
)

// ChallengePayload координирует сборку и строгую Big-Endian сериализацию
// контекста одноразового криптографического челленджа Proof of Possession.
type ChallengePayload struct {
	UserID      string
	SessionID   string
	ServerNonce []byte
	Operation   string // Допустимы строго "register" или "attach-device"
}

// NewChallengePayload конструирует и санирует объект ChallengePayload.
func NewChallengePayload(userID, sessionID string, nonce []byte, op string) *ChallengePayload {
	return &ChallengePayload{
		UserID:      strings.TrimSpace(userID),
		SessionID:   strings.TrimSpace(sessionID),
		ServerNonce: nonce,
		Operation:   strings.TrimSpace(op),
	}
}

// Marshal упаковывает данные структуры в канонический Big-Endian поток байт для отправки в ssh-agent.
// Формат потока:
// version (4B) + context_len (2B) + context + user_id_len (2B) + user_id + session_id_len (2B) + session_id + nonce_len (2B) + nonce + op_len (2B) + op
//
// В случае превышения лимитов полей (64КБ) возвращает nil для предотвращения integer overflow паник.
func (p *ChallengePayload) Marshal() []byte {
	ctxBytes := []byte(ContextAuthChallenge)
	uBytes := []byte(p.UserID)
	sBytes := []byte(p.SessionID)
	opBytes := []byte(p.Operation)

	// Жесткий ИБ-контроль длин полей перед выделением памяти для исключения переполнения uint16
	if len(ctxBytes) > maxFieldLength || len(uBytes) > maxFieldLength ||
		len(sBytes) > maxFieldLength || len(p.ServerNonce) > maxFieldLength ||
		len(opBytes) > maxFieldLength {
		slog.ErrorContext(context.Background(), "Critical serialization anomaly: challenge payload field constraint violated")
		return nil
	}

	size := 4 + 2 + len(ctxBytes) + 2 + len(uBytes) + 2 + len(sBytes) + 2 + len(p.ServerNonce) + 2 + len(opBytes)
	buf := make([]byte, size)

	// version (4B)
	binary.BigEndian.PutUint32(buf[0:4], challengeVersion1)

	// context
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(ctxBytes)))
	copy(buf[6:6+len(ctxBytes)], ctxBytes)

	// user_id
	offset := 6 + len(ctxBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(uBytes)))
	copy(buf[offset+2:offset+2+len(uBytes)], uBytes)

	// session_id
	offset += 2 + len(uBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(sBytes)))
	copy(buf[offset+2:offset+2+len(sBytes)], sBytes)

	// server_nonce
	offset += 2 + len(sBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(p.ServerNonce)))
	copy(buf[offset+2:offset+2+len(p.ServerNonce)], p.ServerNonce)

	// operation
	offset += 2 + len(p.ServerNonce)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(opBytes)))
	copy(buf[offset+2:], opBytes)

	return buf
}

// Destroy принудительно затирает временный случайный nonce сервера внутри структуры.
func (p *ChallengePayload) Destroy() {
	if p == nil {
		return
	}
	for i := range p.ServerNonce {
		p.ServerNonce[i] = 0
	}
	p.ServerNonce = nil
}
