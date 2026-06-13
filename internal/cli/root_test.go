package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"gophkeeper/internal/config"
)

func TestCreateCommand_UsesConfigFromFlags(t *testing.T) {
	v := config.NewViper()

	cmd, err := NewRootCommand(v)
	if err != nil {
		t.Fatalf("NewRootCommand() error = %v", err)
	}

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{
		"--ssh-auth-sock=/tmp/test.sock",
		"create",
		"--type=password",
		"--key=k1",
		"--value=val1",
	})
	cmd.SetContext(context.Background())

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	out := stdout.String()

	if !strings.Contains(out, "ssh auth socket: /tmp/test.sock") {
		t.Fatalf("expected socket path in output, got: %s", out)
	}
}
