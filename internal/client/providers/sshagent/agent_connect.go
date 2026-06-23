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
	ErrSSHAuthSockNotSet         = errors.New("переменная окружения SSH_AUTH_SOCK не задана")
	ErrAgentHasNoKeys            = errors.New("в ssh-agent отсутствуют загруженные ключи")
	ErrKeyNotFound               = errors.New("указанный SSH-ключ не найден в агенте")
	ErrUnsupportedKeyAlgorithm   = errors.New("неподдерживаемый алгоритм SSH-ключа: необходим Ed25519")
	ErrUnexpectedSignatureFormat = errors.New("неверный или поврежденный формат OpenSSH подписи")
	ErrNonDeterministicSignature = errors.New("подпись не детерминирована: обнаружен аппаратный токен")
	ErrEmptyPayload              = errors.New("полезная нагрузка для подписи не может быть пустой")
	ErrNilPublicKey              = errors.New("публичный ключ не может быть nil")
	ErrEmptyFingerprint          = errors.New("фингерпринт ключа не может быть пустым")
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
		slog.Error("Инициализация крипто-сокета отклонена: SSH_AUTH_SOCK отсутствует")
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

	slog.Debug("Закрытие сессии UNIX-сокета ssh-agent")
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
		slog.Warn("Потеря связи с сокетом ssh-agent при вызове List, попытка реконнекта", "error", err)
		if reconnectErr := c.reconnectLocked(); reconnectErr != nil {
			slog.Error("Аварийное переподключение к сокету агента завершилось сбоем", "error", reconnectErr)
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
			slog.Debug("Пропущен невалидный блоб ключа при парсинге в агенте", "error", err)
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
