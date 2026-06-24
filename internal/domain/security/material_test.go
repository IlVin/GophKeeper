package security_test

import (
	"testing"

	"gophkeeper/internal/domain/security"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretBytes_Destroy_ShouldZeroFillMemory проверяет, что метод Destroy
// физически выжигает нулями бинарные массивы секретов в оперативной памяти.
func TestSecretBytes_Destroy_ShouldZeroFillMemory(t *testing.T) {
	secret := security.SecretBytes([]byte{0xDE, 0xAD, 0xBE, 0xEF})

	// Проверяем исходное состояние памяти
	assert.Equal(t, byte(0xDE), secret[0])

	// Запускаем деструктор ИБ-гигиены
	secret.Destroy()

	// Верифицируем полное зануление ячеек RAM
	assert.Equal(t, byte(0), secret[0], "First secret byte must be fully zeroed")
	assert.Equal(t, byte(0), secret[3], "Last secret byte must be fully zeroed")
}

// TestSecretBytes_Clone_ShouldCreateIndependentCopy проверяет изолированность
// клонированных срезов данных в памяти друг от друга.
func TestSecretBytes_Clone_ShouldCreateIndependentCopy(t *testing.T) {
	original := security.SecretBytes([]byte{1, 2, 3})
	cloned := original.Clone()

	require.Equal(t, original, cloned)

	// Модифицируем клон, оригинальный массив не должен измениться
	cloned[0] = 99
	assert.Equal(t, byte(1), original[0], "Modification of cloned slice must not affect original")
}

// TestGenerateRandomKey_Success проверяет успешную генерацию случайных ключей нужной длины.
func TestGenerateRandomKey_Success(t *testing.T) {
	key, err := security.GenerateRandomKey(32)
	require.NoError(t, err)
	require.Len(t, key, 32, "Generated key size must strictly match request")

	defer key.Destroy()
}

// TestGenerateRandomKey_WithInvalidSize_ShouldReturnError проверяет барьер fail-fast при невалидных размерах.
func TestGenerateRandomKey_WithInvalidSize_ShouldReturnError(t *testing.T) {
	key, err := security.GenerateRandomKey(-5)
	assert.Error(t, err)
	assert.Nil(t, key)
}
