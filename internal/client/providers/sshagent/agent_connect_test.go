package sshagent

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestNewFromEnv_WhenVarMissing_ShouldReturnError проверяет срабатывание барьера
// ИБ-валидации, если системная переменная SSH_AUTH_SOCK стерта или пуста.
func TestNewFromEnv_WhenVarMissing_ShouldReturnError(t *testing.T) {
	origSock := os.Getenv("SSH_AUTH_SOCK")
	err := os.Setenv("SSH_AUTH_SOCK", "")
	require.NoError(t, err)

	defer func() {
		_ = os.Setenv("SSH_AUTH_SOCK", origSock)
	}()

	client, err := NewFromEnv()
	assert.ErrorIs(t, err, ErrSSHAuthSockNotSet, "Должна вернуться специфичная ошибка отсутствия переменной")
	assert.Nil(t, client, "Объект клиента при ошибке инициализации должен быть nil")
}

// TestClient_New_WithEmptyPath_ShouldReturnError проверяет fail-fast барьер конструктора при пустом пути.
func TestClient_New_WithEmptyPath_ShouldReturnError(t *testing.T) {
	client, err := New("   ")
	assert.ErrorIs(t, err, ErrSSHAuthSockNotSet)
	assert.Nil(t, client)
}

// TestClient_List_Success_And_Fingerprint проверяет успешное чтение списка ключей
// из сокета и валидацию канонического SHA256 фингерпринта OpenSSH.
func TestClient_List_Success_And_Fingerprint(t *testing.T) {
	sockPath, keyring := startMockAgent(t)
	pubKey := generateTestEd25519Key(t, keyring, "developer@gophkeeper.local")

	client, err := New(sockPath)
	require.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	keys, err := client.List()
	require.NoError(t, err, "Чтение списка ключей из валидного сокета не должно возвращать ошибок")
	require.Len(t, keys, 1, "В списке должен быть ровно один ключ")

	sshPub, err := ssh.NewPublicKey(pubKey)
	require.NoError(t, err)
	expectedFingerprint := FingerprintSHA256(sshPub)

	assert.Equal(t, "developer@gophkeeper.local", keys[0].Comment)
	assert.Equal(t, ssh.KeyAlgoED25519, keys[0].Algorithm)
	assert.Equal(t, expectedFingerprint, keys[0].Fingerprint, "Фингерпринт обязан соответствовать канону OpenSSH")
}

// TestClient_Ping_Success проверяет работоспособность метода проверки связи с демоном.
func TestClient_Ping_Success(t *testing.T) {
	sockPath, keyring := startMockAgent(t)
	generateTestEd25519Key(t, keyring, "ping-key")

	client, err := New(sockPath)
	require.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	err = client.Ping()
	assert.NoError(t, err, "Пинг живого сокета должен завершаться успехом")
}
