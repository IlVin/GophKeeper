package security_test

import (
	"encoding/binary"
	"testing"

	"gophkeeper/internal/domain/security"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChallengePayload_Marshal_Success проверяет каноническую сериализацию
// параметров челленджа и корректность Big-Endian разметки заголовков длин полей.
func TestChallengePayload_Marshal_Success(t *testing.T) {
	nonce := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	payload := security.NewChallengePayload("user-1", "sess-2", nonce, "register")

	// Исполняем сериализацию
	buf := payload.Marshal()
	require.NotEmpty(t, buf)

	// 1. Проверяем первые 4 байта версии протокола (должна быть 1)
	version := binary.BigEndian.Uint32(buf[0:4])
	assert.Equal(t, uint32(1), version, "Первые 4 байта обязаны кодировать версию 1 в Big-Endian")

	// 2. Проверяем заголовок длины контекста (6-й байт)
	ctxLen := binary.BigEndian.Uint16(buf[4:6])
	assert.Equal(t, uint16(len(security.ContextAuthChallenge)), ctxLen)

	// 3. Проверяем извлечение самого контекстного маркера безопасности
	extractedCtx := string(buf[6 : 6+ctxLen])
	assert.Equal(t, security.ContextAuthChallenge, extractedCtx)
}

// TestChallengePayload_Destroy_ShouldZeroFillNonce проверяет корректность работы
// ИБ-деструктора, контролируя обнуление бинарного массива серверного nonce.
func TestChallengePayload_Destroy_ShouldZeroFillNonce(t *testing.T) {
	nonce := []byte{0x01, 0x02, 0x03, 0x04}
	payload := security.NewChallengePayload("u", "s", nonce, "op")

	// Запускаем деструктор
	payload.Destroy()

	// Верифицируем очистку памяти
	assert.Nil(t, payload.ServerNonce, "Ссылка на массив nonce должна быть аннулирована")
}

// TestChallengePayload_Marshal_FieldTooLong_ShouldReturnNil проверяет барьер
// безопасности на переполнение границ типа uint16 при передаче аномально огромной строки.
func TestChallengePayload_Marshal_FieldTooLong_ShouldReturnNil(t *testing.T) {
	// Создаем строку, заведомо превышающую лимит в 65535 байт (65535 + 1)
	hugeString := make([]byte, 65536)
	for i := range hugeString {
		hugeString[i] = 'A'
	}

	payload := security.NewChallengePayload(string(hugeString), "sess", []byte{1}, "op")

	// Маршалинг должен безопасно вернуть nil вместо паники переполнения буфера
	buf := payload.Marshal()
	assert.Nil(t, buf, "Функция обязана вернуть nil, предотвращая integer overflow и некорректное выделение памяти")
}
