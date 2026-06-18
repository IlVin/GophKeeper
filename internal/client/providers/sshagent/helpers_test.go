package sshagent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testSSHAgentEnv contains environment values exported by ssh-agent.
type testSSHAgentEnv struct {
	Sock string
	PID  string
}

// generateTestED25519Key generates a passwordless Ed25519 SSH keypair in t.TempDir()
// and returns the private key path.
func generateTestED25519Key(t *testing.T) string {
	t.Helper()
	requireSSHKeygen(t)

	dir := t.TempDir()
	privateKeyPath := filepath.Join(dir, "id_ed25519_test")

	cmd := exec.Command(
		"ssh-keygen",
		"-q",
		"-t", "ed25519",
		"-a", "64",
		"-N", "",
		"-f", privateKeyPath,
		"-C", "gophkeeper-test-ed25519",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to generate ed25519 test key: %v; output=%s", err, string(out))
	}

	return privateKeyPath
}

// generateTestRSAKey generates a passwordless RSA SSH keypair in t.TempDir()
// and returns the private key path.
func generateTestRSAKey(t *testing.T) string {
	t.Helper()
	requireSSHKeygen(t)

	dir := t.TempDir()
	privateKeyPath := filepath.Join(dir, "id_rsa_test")

	cmd := exec.Command(
		"ssh-keygen",
		"-q",
		"-t", "rsa",
		"-b", "4096",
		"-o",
		"-a", "64",
		"-N", "",
		"-f", privateKeyPath,
		"-C", "gophkeeper-test-rsa",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to generate rsa test key: %v; output=%s", err, string(out))
	}

	return privateKeyPath
}

// readPublicKey reads and parses "<privateKeyPath>.pub".
func readPublicKey(t *testing.T, privateKeyPath string) ssh.PublicKey {
	t.Helper()

	data, err := os.ReadFile(privateKeyPath + ".pub")
	if err != nil {
		t.Fatalf("failed to read public key: %v", err)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	return pub
}

// requireSSHKeygen ensures ssh-keygen is available in PATH.
func requireSSHKeygen(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen binary not found in PATH")
	}
}

// requireSSHAgentBinaries ensures ssh-agent and ssh-add are available in PATH.
func requireSSHAgentBinaries(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("ssh-agent"); err != nil {
		t.Skip("ssh-agent binary not found in PATH")
	}
	if _, err := exec.LookPath("ssh-add"); err != nil {
		t.Skip("ssh-add binary not found in PATH")
	}
}

// startTestSSHAgent starts a real ssh-agent process and configures environment variables for the test.
func startTestSSHAgent(t *testing.T) testSSHAgentEnv {
	t.Helper()
	requireSSHAgentBinaries(t)

	cmd := exec.Command("ssh-agent", "-s")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to start ssh-agent: %v", err)
	}

	env := parseSSHAgentOutput(t, string(out))

	t.Setenv("SSH_AUTH_SOCK", env.Sock)
	t.Setenv("SSH_AGENT_PID", env.PID)

	t.Cleanup(func() {
		killCmd := exec.Command("ssh-agent", "-k")
		killCmd.Env = append(os.Environ(),
			"SSH_AUTH_SOCK="+env.Sock,
			"SSH_AGENT_PID="+env.PID,
		)

		_, _ = killCmd.CombinedOutput()
	})

	return env
}

// addKeyToSSHAgent loads the given private key into the running ssh-agent.
func addKeyToSSHAgent(t *testing.T, env testSSHAgentEnv, privateKeyPath string) {
	t.Helper()

	cmd := exec.Command("ssh-add", privateKeyPath)
	cmd.Env = append(os.Environ(),
		"SSH_AUTH_SOCK="+env.Sock,
		"SSH_AGENT_PID="+env.PID,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to add key to ssh-agent: %v; output=%s", err, string(out))
	}
}

// parseSSHAgentOutput parses ssh-agent shell output.
func parseSSHAgentOutput(t *testing.T, out string) testSSHAgentEnv {
	t.Helper()

	sockRe := regexp.MustCompile(`SSH_AUTH_SOCK=([^;]+);`)
	pidRe := regexp.MustCompile(`SSH_AGENT_PID=([0-9]+);`)

	sockMatch := sockRe.FindStringSubmatch(out)
	pidMatch := pidRe.FindStringSubmatch(out)

	if len(sockMatch) != 2 {
		t.Fatalf("failed to parse SSH_AUTH_SOCK from ssh-agent output: %q", out)
	}
	if len(pidMatch) != 2 {
		t.Fatalf("failed to parse SSH_AGENT_PID from ssh-agent output: %q", out)
	}

	return testSSHAgentEnv{
		Sock: sockMatch[1],
		PID:  pidMatch[1],
	}
}

// mustReadPublicKeyBytes reads raw authorized_keys line bytes from "<privateKeyPath>.pub".
func mustReadPublicKeyBytes(t *testing.T, privateKeyPath string) []byte {
	t.Helper()

	data, err := os.ReadFile(privateKeyPath + ".pub")
	if err != nil {
		t.Fatalf("failed to read public key bytes: %v", err)
	}
	return data
}

// debugKeySummary returns a compact debug string for a generated test key.
func debugKeySummary(t *testing.T, privateKeyPath string) string {
	t.Helper()

	pub := readPublicKey(t, privateKeyPath)
	return fmt.Sprintf("path=%s algo=%s fp=%s", privateKeyPath, pub.Type(), FingerprintSHA256(pub))
}
