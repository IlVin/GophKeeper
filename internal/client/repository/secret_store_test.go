package repository_test

import (
	"testing"
	"time"

	"gophkeeper/internal/client/repository"

	"github.com/stretchr/testify/assert"
)

// TestEncryptedRecord_Destroy_ShouldClearReferences проверяет работу деструктора
// модели зашифрованной записи, контролируя обнуление ссылок на бинарный конверт.
func TestEncryptedRecord_Destroy_ShouldClearReferences(t *testing.T) {
	user := "user-uuid"
	record := &repository.EncryptedRecord{
		ID:        "record-uuid",
		UserID:    &user,
		Name:      "google-token",
		Type:      "text",
		Envelope:  []byte{0x01, 0x02, 0x03},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Проверяем исходное состояние фикстуры
	assert.NotEmpty(t, record.Envelope)
	assert.NotNil(t, record.UserID)

	// Вызываем уничтожение ссылок
	record.Destroy()

	// Верифицируем результат ИБ-гигиены
	assert.Nil(t, record.Envelope, "Ciphertext binary array reference must be cleared")
	assert.Nil(t, record.UserID, "User ID reference must be cleared")
}

// TestEncryptedRecord_DestroyWithNil_ShouldNotPanic проверяет nil pointer protection деструктора.
func TestEncryptedRecord_DestroyWithNil_ShouldNotPanic(t *testing.T) {
	var record *repository.EncryptedRecord = nil
	assert.NotPanics(t, func() {
		record.Destroy()
	})
}
