package security_test

import (
	"testing"

	"gophkeeper/internal/domain/security"

	"github.com/stretchr/testify/assert"
)

// TestDeriveRecordID_ShouldBeDeterministic_And_ValidLength проверяет математический инвариант
// детерминированности UUID v5 и строгое соответствие длины текстового представления.
func TestDeriveRecordID_ShouldBeDeterministic_And_ValidLength(t *testing.T) {
	secretName := "yandex-master-oauth-token"

	// Выполняем два последовательных вызова
	id1 := security.DeriveRecordID(secretName)
	id2 := security.DeriveRecordID(secretName)

	// 1. Проверяем детерминированность вывода
	assert.Equal(t, id1, id2, "Повторные вызовы генератора для одного имени обязаны возвращать идентичный UUID")

	// 2. Проверяем валидность длины строкового UUID (36 символов с дефисами)
	assert.Len(t, id1, 36, "Строковое представление UUID обязан составлять ровно 36 символов")

	// 3. Проверяем, что разные имена порождают разные UUID (отсутствие коллизий)
	idDifferent := security.DeriveRecordID("google-token")
	assert.NotEqual(t, id1, idDifferent, "Разные имена секретов должны порождать уникальные UUID")
}
