package security

import (
	"encoding/binary"
	"strings"
)

const (
	ContextAuthChallenge = "gophkeeper-auth-challenge-v1"
)

// ChallengePayload отвечает за сборку сериализованного контекста одноразового челленджа
type ChallengePayload struct {
	UserID      string
	SessionID   string
	ServerNonce []byte
	Operation   string // "register" или "attach-device"
}

func NewChallengePayload(userID, sessionID string, nonce []byte, op string) *ChallengePayload {
	return &ChallengePayload{
		UserID:      strings.TrimSpace(userID),
		SessionID:   strings.TrimSpace(sessionID),
		ServerNonce: nonce,
		Operation:   strings.TrimSpace(op),
	}
}

// Marshal упаковывает данные в строгий Big-Endian поток байт:
// version (4B) + context_len (2B) + context + user_id_len (2B) + user_id + session_id_len (2B) + session_id + nonce_len (2B) + nonce + op_len (2B) + op
func (p *ChallengePayload) Marshal() []byte {
	ctxBytes := []byte(ContextAuthChallenge)
	uBytes := []byte(p.UserID)
	sBytes := []byte(p.SessionID)
	opBytes := []byte(p.Operation)

	size := 4 + 2 + len(ctxBytes) + 2 + len(uBytes) + 2 + len(sBytes) + 2 + len(p.ServerNonce) + 2 + len(opBytes)
	buf := make([]byte, size)

	binary.BigEndian.PutUint32(buf[0:4], Version1)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(ctxBytes)))
	copy(buf[6:6+len(ctxBytes)], ctxBytes)

	offset := 6 + len(ctxBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(uBytes)))
	copy(buf[offset+2:offset+2+len(uBytes)], uBytes)

	offset += 2 + len(uBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(sBytes)))
	copy(buf[offset+2:offset+2+len(sBytes)], sBytes)

	offset += 2 + len(sBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(p.ServerNonce)))
	copy(buf[offset+2:offset+2+len(p.ServerNonce)], p.ServerNonce)

	offset += 2 + len(p.ServerNonce)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(opBytes)))
	copy(buf[offset+2:], opBytes)

	return buf
}
