package sshagent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// TestClient_ListED25519_Success проверяет фильтрацию ed25519 ключей и
// успешное прохождение математического Self-Test на детерминированность подписи.
func TestClient_ListED25519_Success(t *testing.T) {
	sockPath, keyring := startMockAgent(t)
	generateTestEd25519Key(t, keyring, "deterministic-software-key")

	client, err := New(sockPath)
	require.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	keys, err := client.ListED25519()
	require.NoError(t, err, "Software ed25519 key must successfully pass determinism test")
	require.Len(t, keys, 1)
	assert.Equal(t, "deterministic-software-key", keys[0].Comment)
}

// TestClient_SignED25519Raw_Success проверяет сквозной цикл криптографического
// подписания произвольного пакета байт с извлечением сырой 64-байтной сигнатуры.
func TestClient_SignED25519Raw_Success(t *testing.T) {
	sockPath, keyring := startMockAgent(t)
	generateTestEd25519Key(t, keyring, "crypto-key")

	client, err := New(sockPath)
	require.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	list, err := client.List()
	require.NoError(t, err)
	targetFingerprint := list[0].Fingerprint

	payload := []byte("gophkeeper-secure-derivation-block-v1")
	rawSignature, err := client.SignED25519Raw(targetFingerprint, payload)

	require.NoError(t, err, "Signing request to agent must succeed")
	assert.Len(t, rawSignature, 64, "Raw Ed25519 signature binary must be exactly 64 bytes")
}

// TestClient_FindED25519ByFingerprint_NotFound проверяет генерацию ошибки,
// если в агент передается несуществующий фингерпринт.
func TestClient_FindED25519ByFingerprint_NotFound(t *testing.T) {
	sockPath, keyring := startMockAgent(t)
	generateTestEd25519Key(t, keyring, "some-key")

	client, err := New(sockPath)
	require.NoError(t, err)
	defer func() {
		_ = client.Close()
	}()

	info, err := client.FindED25519ByFingerprint("SHA256:nonexistentfingerprintvalue")
	assert.ErrorIs(t, err, ErrKeyNotFound, "Must return canonical ErrKeyNotFound error")
	assert.Nil(t, info)
}

// TestExtractED25519RawSignature_WithInvalidBlob_ShouldReturnError проверяет барьер
// валидации структуры сигнатур при передаче поврежденного бинарного блоба.
func TestExtractED25519RawSignature_WithInvalidBlob_ShouldReturnError(t *testing.T) {
	// Имитируем поврежденный блоб подписи (размер меньше 64 байт)
	corruptedSignature := &ssh.Signature{
		Format: ssh.KeyAlgoED25519,
		Blob:   []byte("short-corrupted-signature-blob"),
	}

	raw, err := ExtractED25519RawSignature(corruptedSignature)
	assert.Error(t, err, "Attempt to parse invalid blob must cause format error")
	assert.Nil(t, raw)
}
