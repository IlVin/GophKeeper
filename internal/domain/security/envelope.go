// Package security инкапсулирует криптографическое ядро, алгоритмы деривации,
// контекстной защиты AAD и сериализации протоколов GophKeeper.
package security

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Названия криптографических схем контекстов AAD из спецификации
	AADSchemaAccountBootstrap = "gophkeeper-account-bootstrap-aad-v1"
	AADSchemaDeviceMasterKey  = "gophkeeper-device-master-key-aad-v1"
	AADSchemaLocalRecord      = "gophkeeper-record-aad-v1"

	// Константный алгоритм шифрования конверта
	AlgoXChaCha20Poly1305 = "XChaCha20-Poly1305"

	// Максимальный лимит длины поля для защиты uint16 заголовков AAD
	maxAADFieldLength = 65535
)

// Envelope представляет собой структуру версионированного криптографического контейнера,
// сохраняемого в персистентных полях базы данных SQLite.
type Envelope struct {
	Version    uint32 `json:"version"`
	Algorithm  string `json:"algorithm"`
	Nonce      []byte `json:"nonce"`
	AADSchema  string `json:"aad_schema"`
	Ciphertext []byte `json:"ciphertext"` // Содержит шифртекст + хвостовой 16-байтный тег Poly1305
}

// RecordPlaintext представляет собой монолитную структуру данных, которая шифруется в Envelope.
// Она объединяет payload и метаданные, аппаратно защищая сессию от Metadata Leakage.
type RecordPlaintext struct {
	Payload  []byte            `json:"payload"`
	Metadata map[string]string `json:"metadata"`
}

// PackRecordPlaintext собирает plaintext-структуру в байты для шифрования.
func PackRecordPlaintext(payload []byte, metadata map[string]string) ([]byte, error) {
	if metadata == nil {
		metadata = make(map[string]string)
	}
	bytes, err := json.Marshal(RecordPlaintext{
		Payload:  payload,
		Metadata: metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal plaintext structure layout: %w", err)
	}
	return bytes, nil
}

// UnpackRecordPlaintext извлекает payload и metadata из расшифрованных байт монолита.
func UnpackRecordPlaintext(decrypted []byte) ([]byte, map[string]string, error) {
	var plain RecordPlaintext
	if err := json.Unmarshal(decrypted, &plain); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal decrypted structure layout: %w", err)
	}
	return plain.Payload, plain.Metadata, nil
}

// BuildAccountBootstrapAAD собирает Big-Endian контекст AAD для Bootstrap cloud-конверта.
func BuildAccountBootstrapAAD(sshFingerprint string) []byte {
	ctxBytes := []byte(AADSchemaAccountBootstrap)
	fpBytes := []byte(sshFingerprint)

	// ИБ-барьер контроля переполнения типов длины uint16
	if len(ctxBytes) > maxAADFieldLength || len(fpBytes) > maxAADFieldLength {
		slog.ErrorContext(context.Background(), "Critical AAD assembly failure: bootstrap field overflow detected")
		return nil
	}

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

// BuildDeviceMasterKeyAAD собирает Big-Endian контекст AAD для локального контейнера синглтона.
func BuildDeviceMasterKeyAAD(userID *string, deviceID string) []byte {
	ctxBytes := []byte(AADSchemaDeviceMasterKey)
	devIDBytes := []byte(deviceID)

	var uBytes []byte
	if userID != nil && *userID != "" {
		uBytes = []byte(*userID)
	}

	if len(ctxBytes) > maxAADFieldLength || len(uBytes) > maxAADFieldLength || len(devIDBytes) > maxAADFieldLength {
		slog.ErrorContext(context.Background(), "Critical AAD assembly failure: device master key field overflow detected")
		return nil
	}

	size := 4 + 2 + len(ctxBytes) + 2 + len(uBytes) + 2 + len(devIDBytes)
	buf := make([]byte, size)

	binary.BigEndian.PutUint32(buf[0:4], Version1)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(ctxBytes)))
	copy(buf[6:6+len(ctxBytes)], ctxBytes)

	offset := 6 + len(ctxBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(uBytes)))
	if len(uBytes) > 0 {
		copy(buf[offset+2:offset+2+len(uBytes)], uBytes)
	}

	offset += 2 + len(uBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(devIDBytes)))
	copy(buf[offset+2:], devIDBytes)

	return buf
}

// BuildRecordAAD собирает Big-Endian контекст защиты для конкретной записи пользователя.
func BuildRecordAAD(userID *string, recordID string) []byte {
	ctxBytes := []byte(AADSchemaLocalRecord)
	recIDBytes := []byte(recordID)

	var uBytes []byte
	if userID != nil && *userID != "" {
		uBytes = []byte(*userID)
	}

	if len(ctxBytes) > maxAADFieldLength || len(uBytes) > maxAADFieldLength || len(recIDBytes) > maxAADFieldLength {
		slog.ErrorContext(context.Background(), "Critical AAD assembly failure: record field overflow detected")
		return nil
	}

	size := 4 + 2 + len(ctxBytes) + 2 + len(uBytes) + 2 + len(recIDBytes)
	buf := make([]byte, size)

	binary.BigEndian.PutUint32(buf[0:4], Version1)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(ctxBytes)))
	copy(buf[6:6+len(ctxBytes)], ctxBytes)

	offset := 6 + len(ctxBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(uBytes)))
	if len(uBytes) > 0 {
		copy(buf[offset+2:offset+2+len(uBytes)], uBytes)
	}

	offset += 2 + len(uBytes)
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(recIDBytes)))
	copy(buf[offset+2:], recIDBytes)

	return buf
}

// SealEnvelope запечатывает переданный секрет с помощью крипто-шифра XChaCha20-Poly1305 и навешивает AAD.
func SealEnvelope(key SecretBytes, plaintext []byte, aad []byte, schema string) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid symmetric key length: must be exactly 32 bytes")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize xchacha20poly1305 engine: %w", err)
	}

	// Генерируем 24-байтный криптографически стойкий случайный nonce для XChaCha20
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce failed: %w", err)
	}

	// Запечатываем данные (тег Poly1305 дописывается в конец ciphertext автоматически)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	env := &Envelope{
		Version:    Version1,
		Algorithm:  AlgoXChaCha20Poly1305,
		Nonce:      nonce,
		AADSchema:  schema,
		Ciphertext: ciphertext,
	}

	// Сериализуем структуру конверта в JSON для персистентного хранения в СУБД SQLite
	envJSON, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope to json failed: %w", err)
	}

	return envJSON, nil
}

// OpenEnvelope распаковывает крипто-конверт, проверяет целостность тега аутентификации Poly1305 и расшифровывает контент.
func OpenEnvelope(key SecretBytes, envJSON []byte, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid symmetric key length: must be exactly 32 bytes")
	}

	var env Envelope
	if err := json.Unmarshal(envJSON, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope failed: %w", err)
	}

	if env.Version != Version1 {
		return nil, fmt.Errorf("unsupported envelope version: %d", env.Version)
	}
	if env.Algorithm != AlgoXChaCha20Poly1305 {
		return nil, fmt.Errorf("unsupported cipher algorithm: %s", env.Algorithm)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize xchacha20poly1305 decryption engine: %w", err)
	}

	plaintext, err := aead.Open(nil, env.Nonce, env.Ciphertext, aad)
	if err != nil {
		slog.ErrorContext(context.Background(), "Poly1305 cryptographic authentication failed: ciphertext tag mismatch or data tampering tracked")
		return nil, fmt.Errorf("failed to open envelope (integrity check or key failure): %w", err)
	}

	return plaintext, nil
}
