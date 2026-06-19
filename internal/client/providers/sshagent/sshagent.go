// Package sshagent contains adapters for working with an SSH agent via SSH_AUTH_SOCK.
//
// This adapter is responsible for:
//
//   - connecting to a running ssh-agent;
//   - listing loaded public keys;
//   - selecting a key by SHA256 fingerprint;
//   - signing arbitrary payloads through the agent;
//   - extracting canonical raw Ed25519 signature bytes;
//   - performing a deterministic signature self-test required by GophKeeper.
//
// In the GophKeeper security architecture, ssh-agent acts as the root of trust.
// The private SSH key is never read directly by the application and never leaves
// the agent. All proof-of-possession and root secret derivation operations are
// performed through agent-backed signature requests.
package sshagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

const (
	// KeyAlgoED25519 is the SSH key algorithm name for Ed25519 keys.
	//
	// GophKeeper MVP supports only ssh-ed25519 because deterministic signatures
	// are required for AccountUnlockKey derivation.
	KeyAlgoED25519 = ssh.KeyAlgoED25519
)

var (
	ErrSSHAuthSockNotSet         = errors.New("SSH_AUTH_SOCK is not set")
	ErrAgentHasNoKeys            = errors.New("ssh agent has no keys")
	ErrKeyNotFound               = errors.New("ssh key not found in agent")
	ErrUnsupportedKeyAlgorithm   = errors.New("unsupported ssh key algorithm")
	ErrUnexpectedSignatureFormat = errors.New("unexpected ssh signature format")
	ErrNonDeterministicSignature = errors.New("ssh signature is not deterministic")
	ErrEmptyPayload              = errors.New("payload is empty")
	ErrNilPublicKey              = errors.New("public key is nil")
	ErrEmptyFingerprint          = errors.New("fingerprint is empty")
)

type SignerInfo struct {
	Comment     string
	Algorithm   string
	Fingerprint string
	PublicKey   ssh.PublicKey
}

type Client struct {
	socketPath string

	mu   sync.Mutex
	conn net.Conn
	ag   sshagent.Agent
}

func NewFromEnv() (*Client, error) {
	socketPath := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if socketPath == "" {
		return nil, ErrSSHAuthSockNotSet
	}

	return New(socketPath)
}

func New(socketPath string) (*Client, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		return nil, ErrSSHAuthSockNotSet
	}

	c := &Client{
		socketPath: socketPath,
	}

	if err := c.connect(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}

	err := c.conn.Close()
	c.conn = nil
	c.ag = nil
	return err
}

func (c *Client) Ping() error {
	_, err := c.List()
	return err
}

func (c *Client) List() ([]SignerInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureConnectedLocked(); err != nil {
		return nil, err
	}

	keys, err := c.ag.List()
	if err != nil {
		if reconnectErr := c.reconnectLocked(); reconnectErr != nil {
			return nil, err
		}

		keys, err = c.ag.List()
		if err != nil {
			return nil, err
		}
	}

	if len(keys) == 0 {
		return nil, ErrAgentHasNoKeys
	}

	result := make([]SignerInfo, 0, len(keys))
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}

		result = append(result, SignerInfo{
			Comment:     k.Comment,
			Algorithm:   pub.Type(),
			Fingerprint: FingerprintSHA256(pub),
			PublicKey:   pub,
		})
	}

	if len(result) == 0 {
		return nil, ErrAgentHasNoKeys
	}

	return result, nil
}

func (c *Client) ListED25519() ([]SignerInfo, error) {
	keys, err := c.List()
	if err != nil {
		return nil, err
	}

	// Фиксированный тестовый payload для проверки детерминированности на этапе фильтрации
	testPayload := []byte("gophkeeper-crypto-determinism-pre-filter-v1")

	out := make([]SignerInfo, 0, len(keys))
	for _, k := range keys {
		if k.Algorithm == KeyAlgoED25519 {
			// Проверяем ключ на детерминированность прямо в цикле (Инвариант №3)
			// Если ключ не детерминирован, SelfTest вернет ошибку ErrNonDeterministicSignature
			if err := c.SelfTestDeterministicED25519(k.Fingerprint, testPayload); err != nil {
				// Пропускаем аппаратные/несовместимые токены
				continue
			}

			out = append(out, k)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no deterministic software ed25519 keys found in agent", ErrKeyNotFound)
	}

	return out, nil
}

func (c *Client) FindByFingerprint(fingerprint string) (*SignerInfo, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return nil, ErrEmptyFingerprint
	}

	keys, err := c.List()
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		if k.Fingerprint == fingerprint {
			key := k
			return &key, nil
		}
	}

	return nil, ErrKeyNotFound
}

func (c *Client) FindED25519ByFingerprint(fingerprint string) (*SignerInfo, error) {
	info, err := c.FindByFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	if info.Algorithm != KeyAlgoED25519 {
		return nil, ErrUnsupportedKeyAlgorithm
	}

	return info, nil
}

func (c *Client) Sign(fingerprint string, payload []byte) (*ssh.Signature, error) {
	if len(payload) == 0 {
		return nil, ErrEmptyPayload
	}

	info, err := c.FindByFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	return c.signWithPublicKey(info.PublicKey, payload)
}

func (c *Client) SignED25519(fingerprint string, payload []byte) (*ssh.Signature, error) {
	if len(payload) == 0 {
		return nil, ErrEmptyPayload
	}

	info, err := c.FindED25519ByFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	sig, err := c.signWithPublicKey(info.PublicKey, payload)
	if err != nil {
		return nil, err
	}

	if sig == nil || sig.Format != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("%w: got=%v want=%s", ErrUnexpectedSignatureFormat, signatureFormat(sig), ssh.KeyAlgoED25519)
	}

	return sig, nil
}

func (c *Client) SignED25519Raw(fingerprint string, payload []byte) ([]byte, error) {
	sig, err := c.SignED25519(fingerprint, payload)
	if err != nil {
		return nil, err
	}

	return ExtractED25519RawSignature(sig)
}

func (c *Client) SelfTestDeterministicED25519(fingerprint string, payload []byte) error {
	if len(payload) == 0 {
		return ErrEmptyPayload
	}

	sig1, err := c.SignED25519Raw(fingerprint, payload)
	if err != nil {
		return err
	}

	sig2, err := c.SignED25519Raw(fingerprint, payload)
	if err != nil {
		return err
	}

	if !bytes.Equal(sig1, sig2) {
		return ErrNonDeterministicSignature
	}

	return nil
}

// ИСПРАВЛЕНО: Приведен к стандарту OpenSSH (StdEncoding вместо Raw, корректный тримминг знаков '=')
func FingerprintSHA256(pub ssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	b64 := base64.StdEncoding.EncodeToString(sum[:])
	return "SHA256:" + strings.TrimRight(b64, "=")
}

func ExtractED25519RawSignature(sig *ssh.Signature) ([]byte, error) {
	if sig == nil {
		return nil, ErrUnexpectedSignatureFormat
	}

	if sig.Format != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("%w: got=%s want=%s", ErrUnexpectedSignatureFormat, sig.Format, ssh.KeyAlgoED25519)
	}

	if len(sig.Blob) != 64 {
		return nil, fmt.Errorf("%w: invalid ed25519 blob length=%d", ErrUnexpectedSignatureFormat, len(sig.Blob))
	}

	out := make([]byte, 64)
	copy(out, sig.Blob)
	return out, nil
}

// ИСПРАВЛЕНО: Убран повторный c.mu.Lock() для предотвращения взаимной блокировки (Deadlock)
func (c *Client) signWithPublicKey(pub ssh.PublicKey, payload []byte) (*ssh.Signature, error) {
	if pub == nil {
		return nil, ErrNilPublicKey
	}

	// Важно: мьютекс mu уже заблокирован вызывающим методом (Sign или SignED25519)
	if err := c.ensureConnectedLocked(); err != nil {
		return nil, err
	}

	sig, err := c.ag.Sign(pub, payload)
	if err != nil {
		if reconnectErr := c.reconnectLocked(); reconnectErr != nil {
			return nil, err
		}

		sig, err = c.ag.Sign(pub, payload)
		if err != nil {
			return nil, err
		}
	}

	return sig, nil
}

func (c *Client) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connectLocked()
}

func (c *Client) connectLocked() error {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("connect to ssh-agent: %w", err)
	}

	c.conn = conn
	c.ag = sshagent.NewClient(conn)
	return nil
}

func (c *Client) ensureConnectedLocked() error {
	if c.conn != nil && c.ag != nil {
		return nil
	}

	return c.connectLocked()
}

func (c *Client) reconnectLocked() error {
	if c.conn != nil {
		_ = c.conn.Close()
	}

	c.conn = nil
	c.ag = nil

	return c.connectLocked()
}

func signatureFormat(sig *ssh.Signature) string {
	if sig == nil {
		return "<nil>"
	}
	return sig.Format
}
