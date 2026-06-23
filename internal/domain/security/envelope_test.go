package security_test

import (
	"testing"

	"gophkeeper/internal/domain/security"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnvelope_FullCryptoCycle_ShouldSuccess проверяет сквозной цикл шифрования
// и обратной расшифровки полезной нагрузки с валидацией контекста AAD.
func TestEnvelope_FullCryptoCycle_ShouldSuccess(t *testing.T) {
	// Генерируем 32-байтный симметричный мастер-ключ
	mockKey := security.SecretBytes(make([]byte, 32))
	for i := range mockKey {
		mockKey[i] = byte(i)
	}
	defer mockKey.Destroy()

	// 1. Подготавливаем plaintext и контекст AAD записи
	userID := "canonical-user-uuid"
	recordID := "11111111-2222-3333-4444-555555555555"
	aad := security.BuildRecordAAD(&userID, recordID)
	require.NotEmpty(t, aad)

	plaintextPayload := []byte("my-super-secret-password-content-bytes")

	// 2. Упаковываем в JSON монолит
	packedPlain, err := security.PackRecordPlaintext(plaintextPayload, map[string]string{"env": "prod"})
	require.NoError(t, err)

	// 3. Запечатываем конверт XChaCha20-Poly1305
	envelopeJSON, err := security.SealEnvelope(mockKey, packedPlain, aad, security.AADSchemaLocalRecord)
	require.NoError(t, err)
	require.NotEmpty(t, envelopeJSON)

	// 4. Расшифровываем конверт обратно
	decryptedBytes, err := security.OpenEnvelope(mockKey, envelopeJSON, aad)
	require.NoError(t, err, "Расшифровка на валидном ключе и валидном AAD контексте должна пройти успешно")

	// 5. Распаковываем структуру монолита
	extractedPayload, meta, err := security.UnpackRecordPlaintext(decryptedBytes)
	require.NoError(t, err)

	assert.Equal(t, plaintextPayload, extractedPayload)
	assert.Equal(t, "prod", meta["env"])
}

// TestEnvelope_Tampering_ShouldFailPoly1305 проверяет барьер безопасности Poly1305:
// модификация даже одного бита шифртекста должна приводить к полному криптографическому отказу.
func TestEnvelope_Tampering_ShouldFailPoly1305(t *testing.T) {
	mockKey := security.SecretBytes(make([]byte, 32))
	defer mockKey.Destroy()

	aad := security.BuildAccountBootstrapAAD("fingerprint")
	plaintext := []byte("confidential-payload")

	// Запечатываем конверт
	envelopeJSON, err := security.SealEnvelope(mockKey, plaintext, aad, security.AADSchemaAccountBootstrap)
	require.NoError(t, err)

	// Нагло имитируем атаку злоумышленника на диске: подменяем один байт в JSON-строке шифртекста
	// Меняем символ 'a' на 'b' (или любой другой), ломая целостность Poly1305 тега
	for i := range envelopeJSON {
		if envelopeJSON[i] == '"' && i+5 < len(envelopeJSON) {
			envelopeJSON[i+2] ^= 0x01 // Инвертируем бит шифртекста
			break
		}
	}

	// Попытка открыть поврежденный конверт обязана завершиться аварией
	decrypted, err := security.OpenEnvelope(mockKey, envelopeJSON, aad)
	assert.Error(t, err, "Криптографическое ядро обязано заблокировать измененный конверт")
	assert.Nil(t, decrypted)
}
