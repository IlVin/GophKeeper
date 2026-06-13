package sshagent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	xagent "golang.org/x/crypto/ssh/agent"
)

type mockAgent struct {
	listFn func() ([]*xagent.Key, error)
	signFn func(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error)
}

func (m *mockAgent) List() ([]*xagent.Key, error) {
	if m.listFn != nil {
		return m.listFn()
	}
	return nil, nil
}

func (m *mockAgent) Sign(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
	if m.signFn != nil {
		return m.signFn(key, data)
	}
	return nil, nil
}

func (m *mockAgent) Add(key xagent.AddedKey) error {
	return nil
}

func (m *mockAgent) Remove(key cryptossh.PublicKey) error {
	return nil
}

func (m *mockAgent) RemoveAll() error {
	return nil
}

func (m *mockAgent) Lock(passphrase []byte) error {
	return nil
}

func (m *mockAgent) Unlock(passphrase []byte) error {
	return nil
}

func (m *mockAgent) Signers() ([]cryptossh.Signer, error) {
	return nil, nil
}

func (m *mockAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, nil
}

func TestNewFromEnv_ErrWhenMissing(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	_, err := NewFromEnv()
	if !errors.Is(err, ErrSSHAuthSockNotSet) {
		t.Fatalf("expected ErrSSHAuthSockNotSet, got %v", err)
	}
}

func TestNew_ErrWhenEmptyPath(t *testing.T) {
	_, err := New("")
	if !errors.Is(err, ErrSSHAuthSockNotSet) {
		t.Fatalf("expected ErrSSHAuthSockNotSet, got %v", err)
	}
}

func TestNew_ErrWhenSocketUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.sock")
	_, err := New(path)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestClose_NilConn(t *testing.T) {
	c := &Client{}
	if err := c.Close(); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestClose_WithConn(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	c := &Client{
		conn: c1,
		ag:   &mockAgent{},
	}

	if err := c.Close(); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if c.conn != nil {
		t.Fatal("expected conn to be nil after Close")
	}
	if c.ag != nil {
		t.Fatal("expected agent to be nil after Close")
	}
}

func TestFingerprintSHA256(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	pub := readPublicKey(t, privateKeyPath)

	got := FingerprintSHA256(pub)

	sum := sha256.Sum256(pub.Marshal())
	want := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])

	if got != want {
		t.Fatalf("fingerprint mismatch: got=%q want=%q", got, want)
	}
}

func TestExtractED25519RawSignature_OK(t *testing.T) {
	raw := bytes.Repeat([]byte{0xAB}, 64)
	sig := &cryptossh.Signature{
		Format: cryptossh.KeyAlgoED25519,
		Blob:   raw,
	}

	got, err := ExtractED25519RawSignature(sig)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("raw signature mismatch")
	}
	if &got[0] == &raw[0] {
		t.Fatal("expected copied slice, got same backing array")
	}
}

func TestExtractED25519RawSignature_Nil(t *testing.T) {
	_, err := ExtractED25519RawSignature(nil)
	if !errors.Is(err, ErrUnexpectedSignatureFormat) {
		t.Fatalf("expected ErrUnexpectedSignatureFormat, got %v", err)
	}
}

func TestExtractED25519RawSignature_WrongFormat(t *testing.T) {
	sig := &cryptossh.Signature{
		Format: cryptossh.KeyAlgoRSA,
		Blob:   bytes.Repeat([]byte{0x11}, 64),
	}

	_, err := ExtractED25519RawSignature(sig)
	if !errors.Is(err, ErrUnexpectedSignatureFormat) {
		t.Fatalf("expected ErrUnexpectedSignatureFormat, got %v", err)
	}
}

func TestExtractED25519RawSignature_WrongLength(t *testing.T) {
	sig := &cryptossh.Signature{
		Format: cryptossh.KeyAlgoED25519,
		Blob:   bytes.Repeat([]byte{0x11}, 63),
	}

	_, err := ExtractED25519RawSignature(sig)
	if !errors.Is(err, ErrUnexpectedSignatureFormat) {
		t.Fatalf("expected ErrUnexpectedSignatureFormat, got %v", err)
	}
}

func TestList_OK(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	pub := readPublicKey(t, privateKeyPath)

	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{
						Format:  pub.Type(),
						Blob:    pub.Marshal(),
						Comment: "test-key",
					},
				}, nil
			},
		},
		conn: dummyConn{},
	}

	keys, err := c.List()
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].Algorithm != cryptossh.KeyAlgoED25519 {
		t.Fatalf("unexpected algorithm: %s", keys[0].Algorithm)
	}
	if keys[0].Comment != "test-key" {
		t.Fatalf("unexpected comment: %s", keys[0].Comment)
	}
	if keys[0].Fingerprint != FingerprintSHA256(pub) {
		t.Fatalf("unexpected fingerprint: %s", keys[0].Fingerprint)
	}
}

func TestList_ErrNoKeys(t *testing.T) {
	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{}, nil
			},
		},
		conn: dummyConn{},
	}

	_, err := c.List()
	if !errors.Is(err, ErrAgentHasNoKeys) {
		t.Fatalf("expected ErrAgentHasNoKeys, got %v", err)
	}
}

func TestList_SkipsMalformedAndReturnsNoKeys(t *testing.T) {
	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{
						Format:  "ssh-ed25519",
						Blob:    []byte("bad-key"),
						Comment: "broken",
					},
				}, nil
			},
		},
		conn: dummyConn{},
	}

	_, err := c.List()
	if !errors.Is(err, ErrAgentHasNoKeys) {
		t.Fatalf("expected ErrAgentHasNoKeys, got %v", err)
	}
}

func TestList_ReconnectFailsAndReturnsOriginalError(t *testing.T) {
	listErr := errors.New("list failed")

	c := &Client{
		socketPath: filepath.Join(t.TempDir(), "missing.sock"),
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return nil, listErr
			},
		},
		conn: dummyConn{},
	}

	_, err := c.List()
	if !errors.Is(err, listErr) {
		t.Fatalf("expected original list error, got %v", err)
	}
}

func TestListED25519_OK(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	ed := readPublicKey(t, privateKeyPath)
	privateKeyPathRSA := generateTestRSAKey(t)
	rsa := readPublicKey(t, privateKeyPathRSA)

	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: ed.Type(), Blob: ed.Marshal(), Comment: "ed"},
					{Format: rsa.Type(), Blob: rsa.Marshal(), Comment: "rsa"},
				}, nil
			},
		},
		conn: dummyConn{},
	}

	keys, err := c.ListED25519()
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 ed25519 key, got %d", len(keys))
	}
	if keys[0].Algorithm != cryptossh.KeyAlgoED25519 {
		t.Fatalf("unexpected algorithm: %s", keys[0].Algorithm)
	}
}

func TestListED25519_NotFound(t *testing.T) {
	privateKeyPath := generateTestRSAKey(t)
	rsa := readPublicKey(t, privateKeyPath)
	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: rsa.Type(), Blob: rsa.Marshal(), Comment: "rsa"},
				}, nil
			},
		},
		conn: dummyConn{},
	}

	_, err := c.ListED25519()
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestFindByFingerprint_OK(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)

	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: pub.Type(), Blob: pub.Marshal(), Comment: "test"},
				}, nil
			},
		},
		conn: dummyConn{},
	}

	info, err := c.FindByFingerprint(fp)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if info.Fingerprint != fp {
		t.Fatalf("unexpected fingerprint: %s", info.Fingerprint)
	}
}

func TestFindByFingerprint_NotFound(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	pub := readPublicKey(t, privateKeyPath)

	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: pub.Type(), Blob: pub.Marshal(), Comment: "test"},
				}, nil
			},
		},
		conn: dummyConn{},
	}

	_, err := c.FindByFingerprint("SHA256:notfound")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestFindED25519ByFingerprint_OK(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)

	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: pub.Type(), Blob: pub.Marshal(), Comment: "ed"},
				}, nil
			},
		},
		conn: dummyConn{},
	}

	info, err := c.FindED25519ByFingerprint(fp)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if info.Algorithm != cryptossh.KeyAlgoED25519 {
		t.Fatalf("unexpected algorithm: %s", info.Algorithm)
	}
}

func TestFindED25519ByFingerprint_UnsupportedAlgo(t *testing.T) {
	privateKeyPath := generateTestRSAKey(t)
	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)

	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: pub.Type(), Blob: pub.Marshal(), Comment: "rsa"},
				}, nil
			},
		},
		conn: dummyConn{},
	}

	_, err := c.FindED25519ByFingerprint(fp)
	if !errors.Is(err, ErrUnsupportedKeyAlgorithm) {
		t.Fatalf("expected ErrUnsupportedKeyAlgorithm, got %v", err)
	}
}

func TestSign_ErrEmptyPayload(t *testing.T) {
	c := &Client{}
	_, err := c.Sign("fp", nil)
	if !errors.Is(err, ErrEmptyPayload) {
		t.Fatalf("expected ErrEmptyPayload, got %v", err)
	}
}

func TestSign_OK(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)
	payload := []byte("hello")
	wantSig := &cryptossh.Signature{
		Format: cryptossh.KeyAlgoED25519,
		Blob:   bytes.Repeat([]byte{0x22}, 64),
	}

	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: pub.Type(), Blob: pub.Marshal(), Comment: "ed"},
				}, nil
			},
			signFn: func(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
				if !bytes.Equal(key.Marshal(), pub.Marshal()) {
					t.Fatal("unexpected public key passed to Sign")
				}
				if !bytes.Equal(data, payload) {
					t.Fatal("unexpected payload passed to Sign")
				}
				return wantSig, nil
			},
		},
		conn: dummyConn{},
	}

	got, err := c.Sign(fp, payload)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != wantSig {
		t.Fatal("unexpected signature pointer returned")
	}
}

func TestSignED25519_ErrEmptyPayload(t *testing.T) {
	c := &Client{}
	_, err := c.SignED25519("fp", nil)
	if !errors.Is(err, ErrEmptyPayload) {
		t.Fatalf("expected ErrEmptyPayload, got %v", err)
	}
}

func TestSignED25519_UnsupportedKey(t *testing.T) {
	privateKeyPath := generateTestRSAKey(t)
	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)

	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: pub.Type(), Blob: pub.Marshal(), Comment: "rsa"},
				}, nil
			},
		},
		conn: dummyConn{},
	}

	_, err := c.SignED25519(fp, []byte("data"))
	if !errors.Is(err, ErrUnsupportedKeyAlgorithm) {
		t.Fatalf("expected ErrUnsupportedKeyAlgorithm, got %v", err)
	}
}

func TestSignED25519_WrongSignatureFormat(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)

	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: pub.Type(), Blob: pub.Marshal(), Comment: "ed"},
				}, nil
			},
			signFn: func(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
				return &cryptossh.Signature{
					Format: cryptossh.KeyAlgoRSA,
					Blob:   []byte("wrong"),
				}, nil
			},
		},
		conn: dummyConn{},
	}

	_, err := c.SignED25519(fp, []byte("data"))
	if !errors.Is(err, ErrUnexpectedSignatureFormat) {
		t.Fatalf("expected ErrUnexpectedSignatureFormat, got %v", err)
	}
}

func TestSignED25519_OK(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)
	wantSig := &cryptossh.Signature{
		Format: cryptossh.KeyAlgoED25519,
		Blob:   bytes.Repeat([]byte{0x42}, 64),
	}

	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: pub.Type(), Blob: pub.Marshal(), Comment: "ed"},
				}, nil
			},
			signFn: func(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
				return wantSig, nil
			},
		},
		conn: dummyConn{},
	}

	got, err := c.SignED25519(fp, []byte("data"))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != wantSig {
		t.Fatal("unexpected signature pointer returned")
	}
}

func TestSignED25519Raw_OK(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)
	raw := bytes.Repeat([]byte{0x77}, 64)

	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: pub.Type(), Blob: pub.Marshal(), Comment: "ed"},
				}, nil
			},
			signFn: func(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
				return &cryptossh.Signature{
					Format: cryptossh.KeyAlgoED25519,
					Blob:   raw,
				}, nil
			},
		},
		conn: dummyConn{},
	}

	got, err := c.SignED25519Raw(fp, []byte("data"))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("unexpected raw signature bytes")
	}
}

func TestSelfTestDeterministicED25519_OK(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)
	raw := bytes.Repeat([]byte{0x55}, 64)

	signCalls := 0
	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: pub.Type(), Blob: pub.Marshal(), Comment: "ed"},
				}, nil
			},
			signFn: func(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
				signCalls++
				return &cryptossh.Signature{
					Format: cryptossh.KeyAlgoED25519,
					Blob:   raw,
				}, nil
			},
		},
		conn: dummyConn{},
	}

	err := c.SelfTestDeterministicED25519(fp, []byte("payload"))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if signCalls != 2 {
		t.Fatalf("expected 2 sign calls, got %d", signCalls)
	}
}

func TestSelfTestDeterministicED25519_ErrEmptyPayload(t *testing.T) {
	c := &Client{}
	err := c.SelfTestDeterministicED25519("fp", nil)
	if !errors.Is(err, ErrEmptyPayload) {
		t.Fatalf("expected ErrEmptyPayload, got %v", err)
	}
}

func TestSelfTestDeterministicED25519_NonDeterministic(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)

	signCalls := 0
	c := &Client{
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: pub.Type(), Blob: pub.Marshal(), Comment: "ed"},
				}, nil
			},
			signFn: func(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
				signCalls++
				b := make([]byte, 64)
				if _, err := rand.Read(b); err != nil {
					t.Fatalf("rand.Read failed: %v", err)
				}
				return &cryptossh.Signature{
					Format: cryptossh.KeyAlgoED25519,
					Blob:   b,
				}, nil
			},
		},
		conn: dummyConn{},
	}

	err := c.SelfTestDeterministicED25519(fp, []byte("payload"))
	if !errors.Is(err, ErrNonDeterministicSignature) {
		t.Fatalf("expected ErrNonDeterministicSignature, got %v", err)
	}
	if signCalls != 2 {
		t.Fatalf("expected 2 sign calls, got %d", signCalls)
	}
}

func TestSign_ReconnectFailsAndReturnsOriginalSignError(t *testing.T) {
	privateKeyPath := generateTestED25519Key(t)
	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)
	signErr := errors.New("sign failed")

	c := &Client{
		socketPath: filepath.Join(t.TempDir(), "missing.sock"),
		ag: &mockAgent{
			listFn: func() ([]*xagent.Key, error) {
				return []*xagent.Key{
					{Format: pub.Type(), Blob: pub.Marshal(), Comment: "ed"},
				}, nil
			},
			signFn: func(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
				return nil, signErr
			},
		},
		conn: dummyConn{},
	}

	_, err := c.Sign(fp, []byte("payload"))
	if !errors.Is(err, signErr) {
		t.Fatalf("expected original sign error, got %v", err)
	}
}

func TestEnsureConnectedLocked_ConnectsWhenNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.sock")

	c := &Client{
		socketPath: path,
	}

	c.mu.Lock()
	err := c.ensureConnectedLocked()
	c.mu.Unlock()

	if err == nil {
		t.Fatal("expected connect error, got nil")
	}
}

func TestReconnectLocked_ClosesAndReconnects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.sock")
	c1, c2 := net.Pipe()
	defer c2.Close()

	c := &Client{
		socketPath: path,
		conn:       c1,
		ag:         &mockAgent{},
	}

	c.mu.Lock()
	err := c.reconnectLocked()
	c.mu.Unlock()

	if err == nil {
		t.Fatal("expected reconnect error, got nil")
	}
	if c.conn != nil || c.ag != nil {
		t.Fatal("expected conn and agent to be nil after failed reconnect")
	}
}

type dummyConn struct{}

func (dummyConn) Read(b []byte) (int, error)         { return 0, os.ErrClosed }
func (dummyConn) Write(b []byte) (int, error)        { return 0, os.ErrClosed }
func (dummyConn) Close() error                       { return nil }
func (dummyConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (dummyConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (dummyConn) SetDeadline(t time.Time) error      { return nil }
func (dummyConn) SetReadDeadline(t time.Time) error  { return nil }
func (dummyConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return "dummy" }
func (a dummyAddr) String() string  { return string(a) }
