// Package sshagent содержит адаптеры для безопасного взаимодействия с системным
// демоном ssh-agent через UNIX-сокет спецификации SSH_AUTH_SOCK.
//
// В архитектуре безопасности GophKeeper ssh-agent выступает аппаратным или
// программным HSM (модулем безопасности). Приватный ключ никогда не считывается
// приложением в память и не покидает агент. Все операции деривации и Proof of
// Possession выполняются строго через запросы изолированного подписания.
package sshagent

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// Поддерживаемые алгоритмы ключей
const (
	// KeyAlgoED25519 определяет каноническое имя алгоритма Ed25519 в OpenSSH.
	// Поддерживаются строго программные ed25519 ключи из-за требования детерминированности подписи.
	KeyAlgoED25519 = ssh.KeyAlgoED25519
)

var (
	ErrSSHAuthSockNotSet         = errors.New("SSH_AUTH_SOCK environment variable is not set")
	ErrAgentHasNoKeys            = errors.New("no keys loaded in ssh-agent")
	ErrKeyNotFound               = errors.New("specified SSH key not found in agent")
	ErrUnsupportedKeyAlgorithm   = errors.New("unsupported SSH key algorithm: Ed25519 required")
	ErrUnexpectedSignatureFormat = errors.New("invalid or corrupted OpenSSH signature format")
	ErrNonDeterministicSignature = errors.New("signature is not deterministic: hardware token detected")
	ErrEmptyPayload              = errors.New("signing payload cannot be empty")
	ErrNilPublicKey              = errors.New("public key cannot be nil")
	ErrEmptyFingerprint          = errors.New("key fingerprint cannot be empty")
)

// SignerInfo инкапсулирует метаданные и публичную часть извлеченного SSH-ключа.
type SignerInfo struct {
	Comment     string        // Комментарий к ключу (например, email владельца)
	Algorithm   string        // Название алгоритма (ssh-ed25519)
	Fingerprint string        // SHA256 фингерпринт в каноническом формате OpenSSH
	PublicKey   ssh.PublicKey // Распакованный интерфейс публичного ключа
}

// Client координирует потокобезопасный доступ к UNIX-сокету ssh-agent с поддержкой
// автоматического прозрачного восстановления соединений при сбоях дескрипторов.
type Client struct {
	socketPath string

	mu   sync.Mutex
	conn net.Conn
	ag   sshagent.Agent
}

// NewFromEnv конструирует клиент, автоматически считывая путь к сокету из окружения ОС.
func NewFromEnv() (*Client, error) {
	socketPath := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if socketPath == "" {
		slog.Error("Crypto socket initialization rejected: SSH_AUTH_SOCK missing")
		return nil, ErrSSHAuthSockNotSet
	}
	return New(socketPath)
}

// New конструирует клиент по явно указанному файловому пути к сокету.
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

// Close безопасно финализирует UNIX-соединение и очищает внутренние интерфейсы.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}

	slog.Debug("Closing ssh-agent UNIX socket session")
	err := c.conn.Close()
	c.conn = nil
	c.ag = nil
	return err
}

// Ping верифицирует работоспособность сокета демона через тестовый листинг.
func (c *Client) Ping() error {
	_, err := c.List()
	return err
}

// List вычитывает полный плоский перечень всех загруженных в агент ключей.
func (c *Client) List() ([]SignerInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureConnectedLocked(); err != nil {
		return nil, err
	}

	keys, err := c.ag.List()
	if err != nil {
		slog.Warn("Lost connection to ssh-agent socket during List, attempting reconnect", "error", err)
		if reconnectErr := c.reconnectLocked(); reconnectErr != nil {
			slog.Error("Emergency agent socket reconnect failed", "error", reconnectErr)
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
			slog.Debug("Skipped invalid key blob during agent parsing", "error", err)
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

// FingerprintSHA256 вычисляет SHA256-хеш публичного ключа и приводит его
// к строгому криптографическому OpenSSH-стандарту (StdEncoding без хвостовых знаков '=').
func FingerprintSHA256(pub ssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	b64 := base64.StdEncoding.EncodeToString(sum[:])
	return "SHA256:" + strings.TrimRight(b64, "=")
}
