//go:build functional

package sshagent

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestFunctional_NewFromEnv_List_FindAndVerifySign(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping functional ssh-agent tests in short mode")
	}

	privateKeyPath := generateTestED25519Key(t)

	env := startTestSSHAgent(t)
	addKeyToSSHAgent(t, env, privateKeyPath)

	pub := readPublicKey(t, privateKeyPath)
	wantFP := FingerprintSHA256(pub)

	client, err := NewFromEnv()
	if err != nil {
		t.Fatalf("NewFromEnv failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	if err := client.Ping(); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}

	keys, err := client.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("expected at least one key in ssh-agent")
	}

	found := false
	for _, k := range keys {
		if k.Fingerprint == wantFP {
			found = true
			if k.Algorithm != ssh.KeyAlgoED25519 {
				t.Fatalf("unexpected algorithm: got=%s want=%s", k.Algorithm, ssh.KeyAlgoED25519)
			}
		}
	}
	if !found {
		t.Fatalf("expected fingerprint %s among listed keys", wantFP)
	}

	info, err := client.FindByFingerprint(wantFP)
	if err != nil {
		t.Fatalf("FindByFingerprint failed: %v", err)
	}
	if info.Fingerprint != wantFP {
		t.Fatalf("unexpected fingerprint: got=%s want=%s", info.Fingerprint, wantFP)
	}

	infoED, err := client.FindED25519ByFingerprint(wantFP)
	if err != nil {
		t.Fatalf("FindED25519ByFingerprint failed: %v", err)
	}
	if infoED.Algorithm != ssh.KeyAlgoED25519 {
		t.Fatalf("unexpected algorithm: got=%s want=%s", infoED.Algorithm, ssh.KeyAlgoED25519)
	}

	payload := []byte("gophkeeper-functional-sign-payload")

	sig, err := client.SignED25519(wantFP, payload)
	if err != nil {
		t.Fatalf("SignED25519 failed: %v", err)
	}
	if err := pub.Verify(payload, sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	raw, err := client.SignED25519Raw(wantFP, payload)
	if err != nil {
		t.Fatalf("SignED25519Raw failed: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("unexpected raw signature length: got=%d want=64", len(raw))
	}

	if err := client.SelfTestDeterministicED25519(wantFP, payload); err != nil {
		t.Fatalf("SelfTestDeterministicED25519 failed: %v", err)
	}
}

func TestFunctional_NewWithExplicitSocketPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping functional ssh-agent tests in short mode")
	}

	privateKeyPath := generateTestED25519Key(t)

	env := startTestSSHAgent(t)
	addKeyToSSHAgent(t, env, privateKeyPath)

	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)

	client, err := New(env.Sock)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	payload := []byte("functional-explicit-socket")
	sig, err := client.SignED25519(fp, payload)
	if err != nil {
		t.Fatalf("SignED25519 failed: %v", err)
	}

	if err := pub.Verify(payload, sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestFunctional_SignED25519Raw_IsDeterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping functional ssh-agent tests in short mode")
	}

	privateKeyPath := generateTestED25519Key(t)

	env := startTestSSHAgent(t)
	addKeyToSSHAgent(t, env, privateKeyPath)

	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)

	client, err := NewFromEnv()
	if err != nil {
		t.Fatalf("NewFromEnv failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	payload := []byte("deterministic-payload")

	sig1, err := client.SignED25519Raw(fp, payload)
	if err != nil {
		t.Fatalf("first SignED25519Raw failed: %v", err)
	}

	sig2, err := client.SignED25519Raw(fp, payload)
	if err != nil {
		t.Fatalf("second SignED25519Raw failed: %v", err)
	}

	if !bytes.Equal(sig1, sig2) {
		t.Fatal("expected deterministic raw signatures, got different values")
	}
}

func TestFunctional_FindByFingerprint_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping functional ssh-agent tests in short mode")
	}

	privateKeyPath := generateTestED25519Key(t)
	env := startTestSSHAgent(t)
	addKeyToSSHAgent(t, env, privateKeyPath)

	client, err := NewFromEnv()
	if err != nil {
		t.Fatalf("NewFromEnv failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	_, err = client.FindByFingerprint("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestFunctional_SignED25519_EmptyPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping functional ssh-agent tests in short mode")
	}

	privateKeyPath := generateTestED25519Key(t)
	env := startTestSSHAgent(t)
	addKeyToSSHAgent(t, env, privateKeyPath)

	pub := readPublicKey(t, privateKeyPath)
	fp := FingerprintSHA256(pub)

	client, err := NewFromEnv()
	if err != nil {
		t.Fatalf("NewFromEnv failed: %v", err)
	}
	defer func() {
		_ = client.Close()
	}()

	_, err = client.SignED25519(fp, nil)
	if !errors.Is(err, ErrEmptyPayload) {
		t.Fatalf("expected ErrEmptyPayload, got %v", err)
	}
}

func TestFunctional_NewFromEnv_ErrWhenSocketDoesNotExist(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping functional ssh-agent tests in short mode")
	}

	t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "missing.sock"))

	_, err := NewFromEnv()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
