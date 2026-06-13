// Package agent contains adapters for working with an SSH agent via SSH_AUTH_SOCK.
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
	// This adapter currently relies on ssh-ed25519 for deterministic signature
	// behavior required by the MVP derivation flow.
	KeyAlgoED25519 = ssh.KeyAlgoED25519
)

// Common adapter errors returned by the ssh-agent client.
var (
	// ErrSSHAuthSockNotSet indicates that SSH_AUTH_SOCK is missing or empty.
	ErrSSHAuthSockNotSet = errors.New("SSH_AUTH_SOCK is not set")

	// ErrAgentHasNoKeys indicates that the ssh-agent is reachable but does not
	// currently expose any usable keys.
	ErrAgentHasNoKeys = errors.New("ssh agent has no keys")

	// ErrKeyNotFound indicates that a requested key could not be found in the agent.
	ErrKeyNotFound = errors.New("ssh key not found in agent")

	// ErrUnsupportedKeyAlgorithm indicates that a key exists but its algorithm
	// is not supported for the requested operation.
	ErrUnsupportedKeyAlgorithm = errors.New("unsupported ssh key algorithm")

	// ErrUnexpectedSignatureFormat indicates that the returned SSH signature does
	// not match the expected format or binary shape.
	ErrUnexpectedSignatureFormat = errors.New("unexpected ssh signature format")

	// ErrNonDeterministicSignature indicates that signing the same payload twice
	// produced different raw signatures.
	ErrNonDeterministicSignature = errors.New("ssh signature is not deterministic")

	// ErrEmptyPayload indicates that an attempt was made to sign an empty payload.
	ErrEmptyPayload = errors.New("payload is empty")
)

// SignerInfo describes a single public key currently loaded in ssh-agent.
//
// The structure contains both display metadata and the parsed ssh.PublicKey,
// allowing higher layers to select a key by fingerprint and use its public
// material for signing requests.
type SignerInfo struct {
	// Comment is the human-readable comment attached to the key inside ssh-agent.
	Comment string

	// Algorithm is the SSH algorithm name, for example "ssh-ed25519".
	Algorithm string

	// Fingerprint is the OpenSSH-style SHA256 fingerprint of the public key.
	Fingerprint string

	// PublicKey is the parsed SSH public key object.
	PublicKey ssh.PublicKey
}

// Client is an adapter over an ssh-agent Unix socket.
//
// The client maintains a reusable connection to the agent and exposes helper
// methods for key enumeration, lookup, and signing. It is safe for concurrent
// use by multiple goroutines because access to the underlying connection is
// serialized with a mutex.
type Client struct {
	socketPath string

	mu   sync.Mutex
	conn net.Conn
	ag   sshagent.Agent
}

// NewFromEnv creates a new ssh-agent adapter using the SSH_AUTH_SOCK environment variable.
//
// It returns ErrSSHAuthSockNotSet if the environment variable is missing or empty.
// The function also establishes the initial connection to the agent.
func NewFromEnv() (*Client, error) {
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if strings.TrimSpace(socketPath) == "" {
		return nil, ErrSSHAuthSockNotSet
	}

	return New(socketPath)
}

// New creates a new ssh-agent adapter for the provided Unix socket path.
//
// The function validates that the path is not empty and immediately attempts to
// connect to the agent. If the connection cannot be established, an error is returned.
func New(socketPath string) (*Client, error) {
	if strings.TrimSpace(socketPath) == "" {
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

// Close closes the underlying connection to ssh-agent.
//
// Close is idempotent: if the connection is already closed, it returns nil.
// After Close, the client may reconnect lazily on the next operation that needs
// agent access.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.ag = nil
		return err
	}

	return nil
}

// Ping verifies that the agent connection is alive and usable.
//
// Internally, it performs a key listing operation. If the agent is unavailable
// or the connection is stale, an error is returned.
func (c *Client) Ping() error {
	_, err := c.List()
	return err
}

// List returns all usable keys currently exposed by ssh-agent.
//
// The method parses public keys returned by the agent and converts them into
// SignerInfo values containing algorithm, fingerprint, comment, and parsed key data.
//
// If the connection has become stale, the adapter attempts a transparent reconnect.
// If the agent has no keys, ErrAgentHasNoKeys is returned.
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
			// Skip malformed entries instead of failing the whole listing.
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

// ListED25519 returns only ssh-ed25519 keys currently available in ssh-agent.
//
// This helper is intended for the GophKeeper MVP, where only Ed25519 keys are
// accepted for root secret derivation. If no Ed25519 keys are present, ErrKeyNotFound
// is returned.
func (c *Client) ListED25519() ([]SignerInfo, error) {
	keys, err := c.List()
	if err != nil {
		return nil, err
	}

	out := make([]SignerInfo, 0, len(keys))
	for _, k := range keys {
		if k.Algorithm == KeyAlgoED25519 {
			out = append(out, k)
		}
	}

	if len(out) == 0 {
		return nil, ErrKeyNotFound
	}

	return out, nil
}

// FindByFingerprint returns a key description by OpenSSH-style SHA256 fingerprint.
//
// The fingerprint must match the format returned by FingerprintSHA256, for example:
// "SHA256:...".
//
// If the key is not present in the agent, ErrKeyNotFound is returned.
func (c *Client) FindByFingerprint(fingerprint string) (*SignerInfo, error) {
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

// FindED25519ByFingerprint returns an ssh-ed25519 key by fingerprint.
//
// If a key with the requested fingerprint exists but is not an Ed25519 key,
// ErrUnsupportedKeyAlgorithm is returned. If the key is missing, ErrKeyNotFound
// is returned.
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

// Sign signs the provided payload with the key identified by fingerprint.
//
// The payload is sent to ssh-agent as-is. The private key remains inside the agent.
// The returned value is the SSH signature structure produced by the agent.
//
// If payload is empty, ErrEmptyPayload is returned.
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

// SignED25519 signs the provided payload with an ssh-ed25519 key identified by fingerprint.
//
// This method enforces both key selection and signature format validation for the
// Ed25519 case required by the derivation flow. If the located key is not Ed25519,
// ErrUnsupportedKeyAlgorithm is returned.
//
// If payload is empty, ErrEmptyPayload is returned.
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

	if sig.Format != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("%w: got=%s want=%s", ErrUnexpectedSignatureFormat, sig.Format, ssh.KeyAlgoED25519)
	}

	return sig, nil
}

// SignED25519Raw signs the payload and returns the canonical raw 64-byte Ed25519 signature.
//
// This helper is intended for use in deterministic key derivation flows where the
// exact binary signature output is used as KDF input. The method first performs
// an Ed25519-only signing operation and then extracts the raw signature bytes.
func (c *Client) SignED25519Raw(fingerprint string, payload []byte) ([]byte, error) {
	sig, err := c.SignED25519(fingerprint, payload)
	if err != nil {
		return nil, err
	}

	raw, err := ExtractED25519RawSignature(sig)
	if err != nil {
		return nil, err
	}

	return raw, nil
}

// SelfTestDeterministicED25519 verifies that signing the same payload twice yields
// identical raw Ed25519 signatures.
//
// This check is required by the GophKeeper MVP security model before using an
// ssh-agent-backed key for root secret derivation. If the two signatures differ,
// ErrNonDeterministicSignature is returned.
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

// FingerprintSHA256 returns the OpenSSH-style SHA256 fingerprint for a public key.
//
// The resulting string has the form "SHA256:<base64-without-padding>" and is
// suitable for stable key identification inside the application.
func FingerprintSHA256(pub ssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ExtractED25519RawSignature extracts the canonical 64-byte raw Ed25519 signature
// from an SSH signature object.
//
// For ssh-ed25519 signatures, ssh.Signature.Blob is expected to contain exactly
// 64 raw signature bytes. If the format or size is unexpected, an error is returned.
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

// signWithPublicKey signs a payload using the specified parsed public key as agent selector.
//
// The ssh-agent protocol identifies the private key to use by its corresponding
// public key. If the connection is stale, this method attempts a transparent reconnect.
func (c *Client) signWithPublicKey(pub ssh.PublicKey, payload []byte) (*ssh.Signature, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

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

// connect establishes the initial connection to the ssh-agent socket.
//
// This is a locking wrapper over connectLocked.
func (c *Client) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connectLocked()
}

// connectLocked establishes a connection to the ssh-agent socket without locking.
//
// The caller must already hold c.mu.
func (c *Client) connectLocked() error {
	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("connect to ssh-agent: %w", err)
	}

	c.conn = conn
	c.ag = sshagent.NewClient(conn)
	return nil
}

// ensureConnectedLocked ensures that the adapter has an active agent connection.
//
// If no connection exists, a new one is established. The caller must already hold c.mu.
func (c *Client) ensureConnectedLocked() error {
	if c.conn != nil && c.ag != nil {
		return nil
	}
	return c.connectLocked()
}

// reconnectLocked drops the current connection and establishes a new one.
//
// This helper is used after agent operations fail due to a stale or broken socket.
// The caller must already hold c.mu.
func (c *Client) reconnectLocked() error {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = nil
	c.ag = nil
	return c.connectLocked()
}
