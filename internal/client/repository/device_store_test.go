package repository

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLocalDeviceState_Destroy_ShouldZeroFillSensitiveData проверяет, что
// метод Destroy принудительно зануляет бинарный массив соли и очищает ссылки на конверты.
func TestLocalDeviceState_Destroy_ShouldZeroFillSensitiveData(t *testing.T) {
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}

	state := &LocalDeviceState{
		DeviceID:                "test-uuid",
		AccountSalt:             salt,
		DeviceMasterKeyEnvelope: []byte{9, 9, 9},
	}

	// Проверяем исходное состояние памяти
	assert.Equal(t, byte(1), state.AccountSalt[0])
	assert.NotEmpty(t, state.DeviceMasterKeyEnvelope)

	// Запускаем уничтожение данных в RAM
	state.Destroy()

	// Верифицируем ИБ-гигиену
	assert.Equal(t, byte(0), state.AccountSalt[0], "Первый байт соли должен быть выжжен нулем")
	assert.Equal(t, byte(0), state.AccountSalt[31], "Последний байт соли должен быть выжжен нулем")
	assert.Nil(t, state.DeviceMasterKeyEnvelope, "Ссылка на конверт мастер-ключа должна быть стерта")
}

// TestLocalDeviceState_DestroyWithNil_ShouldNotPanic проверяет nil pointer protection деструктора.
func TestLocalDeviceState_DestroyWithNil_ShouldNotPanic(t *testing.T) {
	var state *LocalDeviceState = nil
	assert.NotPanics(t, func() {
		state.Destroy()
	})
}
