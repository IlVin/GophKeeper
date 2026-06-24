package commands

import (
	"testing"

	"gophkeeper/internal/client/providers/sshagent"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSelectEngineKey_WithSingleKey_ShouldAutoSelect проверяет сценарий,
// когда в агенте находится ровно один ключ — он должен выбраться автоматически.
func TestSelectEngineKey_WithSingleKey_ShouldAutoSelect(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)

	mockKeys := []sshagent.SignerInfo{
		{Fingerprint: "SHA256:key1111111111111111111111111111111111111111", Comment: "user@home", Algorithm: "ssh-ed25519"},
	}

	selected, err := cli.selectEngineKey(mockKeys)
	require.NoError(t, err)
	assert.Equal(t, "SHA256:key1111111111111111111111111111111111111111", selected.Fingerprint)
}

// TestSelectEngineKey_WithMultipleKeysAndValidSelector_ShouldSelectTarget проверяет сценарий,
// когда ключей несколько, но пользователь передал точное совпадение через Viper.
func TestSelectEngineKey_WithMultipleKeysAndValidSelector_ShouldSelectTarget(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)
	v.Set("app.ssh_key_selector", "work-key") // Set selector by comment

	mockKeys := []sshagent.SignerInfo{
		{Fingerprint: "SHA256:key1", Comment: "home-key", Algorithm: "ssh-ed25519"},
		{Fingerprint: "SHA256:key2", Comment: "work-key", Algorithm: "ssh-ed25519"},
	}

	selected, err := cli.selectEngineKey(mockKeys)
	require.NoError(t, err)
	assert.Equal(t, "SHA256:key2", selected.Fingerprint)
}

// TestSelectEngineKey_WithMultipleKeysAndNoSelector_ShouldReturnDiagnosticMap проверяет сценарий,
// когда ключей несколько, а флаг отсутствует — селектор обязан вернуть ошибку с картой ключей.
func TestSelectEngineKey_WithMultipleKeysAndNoSelector_ShouldReturnDiagnosticMap(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)

	mockKeys := []sshagent.SignerInfo{
		{Fingerprint: "SHA256:key1", Comment: "home-key", Algorithm: "ssh-ed25519"},
		{Fingerprint: "SHA256:key2", Comment: "work-key", Algorithm: "ssh-ed25519"},
	}

	selected, err := cli.selectEngineKey(mockKeys)
	assert.Error(t, err, "Should return error requiring flag")
	assert.Contains(t, err.Error(), "Multiple compatible Ed25519 keys found in your ssh-agent")
	assert.Empty(t, selected.Fingerprint)
}
