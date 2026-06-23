package repository

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestUser_Destroy_ShouldZeroFillSensitiveData проверяет, что метод Destroy
// физически выжигает массивы солей аккаунта нулями для соблюдения RAM Hygiene.
func TestUser_Destroy_ShouldZeroFillSensitiveData(t *testing.T) {
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}

	user := &User{
		ID:                   "user-uuid",
		CanonicalAccountSalt: salt,
		SshPublicKey:         []byte{9, 9, 9},
	}

	// Вызываем уничтожение секретов в RAM
	user.Destroy()

	// Верифицируем гигиену оперативной памяти
	assert.Equal(t, byte(0), user.CanonicalAccountSalt[0], "Первый байт соли должен быть занулен")
	assert.Equal(t, byte(0), user.CanonicalAccountSalt[31], "Последний байт соли должен быть занулен")
	assert.Nil(t, user.SshPublicKey, "Ссылка на бинарный массив публичного ключа должна быть стерта")
}

// TestChallengeSession_Destroy_ShouldClearNonce проверяет очистку одноразовых нонсов.
func TestChallengeSession_Destroy_ShouldClearNonce(t *testing.T) {
	session := &ChallengeSession{
		ID:          "sess-uuid",
		ServerNonce: []byte{0xAA, 0xBB},
	}

	session.Destroy()
	assert.Nil(t, session.ServerNonce, "Ссылка на массив серверного нонса должна быть полностью аннулирована")
}
