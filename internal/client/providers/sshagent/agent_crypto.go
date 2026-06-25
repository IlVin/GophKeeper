package sshagent

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// ListED25519 возвращает отфильтрованный список строго совместимых ed25519 ключей.
//
// Функция реализует Инвариант №3: каждый ключ в цикле подписывает тестовый пакет
// дважды. Если подписи не совпадают, ключ отсекается как аппаратный токен (YubiKey),
// генерирующий случайный рандомизированный nonce, не пригодный для стабильной деривации.
func (c *Client) ListED25519() ([]SignerInfo, error) {
	keys, err := c.List()
	if err != nil {
		return nil, err
	}

	testPayload := []byte("gophkeeper-crypto-determinism-pre-filter-v1")
	out := make([]SignerInfo, 0, len(keys))

	for _, k := range keys {
		if k.Algorithm == KeyAlgoED25519 {
			slog.Debug("Starting security test for key signature determinism",
				slog.String("fingerprint", k.Fingerprint),
			)
			if err := c.SelfTestDeterministicED25519(k.Fingerprint, testPayload); err != nil {
				slog.Warn("Key rejected: randomized hardware signature detected",
					slog.String("fingerprint", k.Fingerprint),
				)
				continue
			}
			out = append(out, k)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no deterministic software ed25519 keys in agent", ErrKeyNotFound)
	}

	return out, nil
}

// FindByFingerprint осуществляет поиск метаданных ключа по его SHA256-фингерпринту.
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

// FindED25519ByFingerprint находит ключ по фингерпринту с жесткой валидацией алгоритма Ed25519.
func (c *Client) FindED25519ByFingerprint(fingerprint string) (*SignerInfo, error) {
	info, err := c.FindByFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}

	if info.Algorithm != KeyAlgoED25519 {
		slog.ErrorContext(context.Background(), "Requested key does not match ed25519 standard",
			slog.String("algo", info.Algorithm),
		)
		return nil, ErrUnsupportedKeyAlgorithm
	}
	return info, nil
}

// Sign запрашивает у агента подпись произвольного пакета байт на базе фингерпринта.
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

// SignED25519 запрашивает подпись с гарантированной проверкой возвращаемого формата OpenSSH Ed25519.
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
		return nil, fmt.Errorf("%w: got format %s, expected %s", ErrUnexpectedSignatureFormat, signatureFormat(sig), ssh.KeyAlgoED25519)
	}
	return sig, nil
}

// SignED25519Raw запрашивает подпись и извлекает из неё чистый плоский 64-байтный массив подписи Ed25519.
func (c *Client) SignED25519Raw(fingerprint string, payload []byte) ([]byte, error) {
	sig, err := c.SignED25519(fingerprint, payload)
	if err != nil {
		return nil, err
	}
	return ExtractED25519RawSignature(sig)
}

// SelfTestDeterministicED25519 математически проверяет идентичность двух последовательных
// подписей одного пакета, гарантируя программную изоляцию nonce алгоритма.
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

// ExtractED25519RawSignature извлекает чистые 64 байта подписи из обертки структуры OpenSSH.
func ExtractED25519RawSignature(sig *ssh.Signature) ([]byte, error) {
	if sig == nil {
		return nil, ErrUnexpectedSignatureFormat
	}

	if sig.Format != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("%w: got format %s, expected %s", ErrUnexpectedSignatureFormat, sig.Format, ssh.KeyAlgoED25519)
	}

	if len(sig.Blob) != 64 {
		return nil, fmt.Errorf("%w: invalid ed25519 signature blob size %d (expected 64)", ErrUnexpectedSignatureFormat, len(sig.Blob))
	}

	out := make([]byte, 64)
	copy(out, sig.Blob)
	return out, nil
}

// signWithPublicKey является низкоуровневым потокобезопасным методом отправки байт в сокет агента.
func (c *Client) signWithPublicKey(pub ssh.PublicKey, payload []byte) (*ssh.Signature, error) {
	if pub == nil {
		return nil, ErrNilPublicKey
	}

	if err := c.ensureConnectedLocked(); err != nil {
		return nil, err
	}

	sig, err := c.ag.Sign(pub, payload)
	if err != nil {
		slog.Warn("Connection lost to ssh-agent socket during Sign, attempting reconnect",
			slog.Any("error", err),
		)
		if reconnectErr := c.reconnectLocked(); reconnectErr != nil {
			slog.ErrorContext(context.Background(), "Emergency reconnect during signing failed",
				slog.Any("error", reconnectErr),
			)
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
		return fmt.Errorf("establish unix connection to socket: %w", err)
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
