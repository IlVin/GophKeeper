package security_test

import (
	"encoding/binary"
	"testing"

	"gophkeeper/internal/domain/security"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDerivationPayload_Marshal_Success проверяет каноническую сериализацию
// контекста деривации и корректность Big-Endian разметки длин полей.
func TestDerivationPayload_Marshal_Success(t *testing.T) {
	mockFingerprint := "SHA256:u1234567890abcdefghijklmnopqrstuvwxyz123"
	payload := security.NewDerivationPayload(mockFingerprint)

	// Выполняем маршалинг
	buf := payload.Marshal()
	require.NotEmpty(t, buf)

	// 1. Проверяем первые 4 байта версии протокола (должна быть 1)
	version := binary.BigEndian.Uint32(buf[0:4])
	assert.Equal(t, uint32(1), version, "Первые 4 байта обязаны кодировать Version1 (1) в Big-Endian")

	// 2. Проверяем заголовок длины контекста (байты 4-6)
	ctxLen := binary.BigEndian.Uint16(buf[4:6])
	assert.Equal(t, uint16(len(security.ContextAccountUnlock)), ctxLen)

	// 3. Проверяем извлечение самого контекстного маркера деривации
	extractedCtx := string(buf[6 : 6+ctxLen])
	assert.Equal(t, security.ContextAccountUnlock, extractedCtx, "Маркер контекста должен точно совпадать")

	// 4. Проверяем заголовок длины фингерпринта на правильном смещении
	offset := 6 + int(ctxLen)
	fpLen := binary.BigEndian.Uint16(buf[offset : offset+2])
	assert.Equal(t, uint16(len(mockFingerprint)), fpLen)

	// 5. Проверяем извлечение самого фингерпринта из хвоста буфера
	extractedFp := string(buf[offset+2:])
	assert.Equal(t, mockFingerprint, extractedFp, "Фингерпринт в буфере должен совпадать с исходным")
}

// TestDerivationPayload_Marshal_FieldTooLong_ShouldReturnNil проверяет барьер
// ИБ-безопасности на переполнение границ типа uint16 при передаче аномально огромной строки.
func TestDerivationPayload_Marshal_FieldTooLong_ShouldReturnNil(t *testing.T) {
	// Генерируем строку фингерпринта, превышающую лимит uint16 в 65535 байт (65535 + 1)
	hugeFingerprintBytes := make([]byte, 65536)
	for i := range hugeFingerprintBytes {
		hugeFingerprintBytes[i] = 'F'
	}

	payload := security.NewDerivationPayload(string(hugeFingerprintBytes))

	// Конвейер обязан вернуть nil вместо паники нарушения границ среза буфера
	buf := payload.Marshal()
	assert.Nil(t, buf, "Функция обязана вернуть nil, предотвращая integer overflow паники")
}
