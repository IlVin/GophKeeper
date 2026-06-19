package sshcheck

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/agent"
)

var ErrSSHAgentUnavailable = errors.New("ssh agent unavailable")

func RequireAgent() error {
	sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if sock == "" {
		return fmt.Errorf("%w: SSH_AUTH_SOCK is not set", ErrSSHAgentUnavailable)
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return fmt.Errorf("%w: connect to SSH_AUTH_SOCK %q: %v", ErrSSHAgentUnavailable, sock, err)
	}
	defer conn.Close()

	agentClient := agent.NewClient(conn)
	signers, err := agentClient.Signers()
	if err != nil {
		return fmt.Errorf("%w: ssh-agent is not responding correctly: %v", ErrSSHAgentUnavailable, err)
	}

	if len(signers) == 0 {
		return fmt.Errorf("%w: no SSH keys loaded in ssh-agent", ErrSSHAgentUnavailable)
	}

	return nil
}

func FormatSSHAgentHelp() string {
	return `GophKeeper requires a working ssh-agent for this command.

Recovery steps:
  1. Generate an SSH key if you do not have one:
     ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519

  2. Start ssh-agent:
     eval "$(ssh-agent -s)"

  3. Add your key to the agent:
     ssh-add ~/.ssh/id_ed25519

  4. Retry the command.`
}
