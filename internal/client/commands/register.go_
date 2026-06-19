package commands

import (
	"fmt"
	"os"

	"gophkeeper/internal/client/providers/grpc"
	"gophkeeper/internal/client/providers/sshagent"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

type RegisterConfig struct {
	Login      string
	PubKeyPath string
	ServerAddr string
}

func LoadRegisterConfig(cmd *cobra.Command) (RegisterConfig, error) {
	login, err := cmd.Flags().GetString("login")
	if err != nil {
		return RegisterConfig{}, fmt.Errorf("get flag login: %w", err)
	}

	pubKeyPath, err := cmd.Flags().GetString("pub-key")
	if err != nil {
		return RegisterConfig{}, fmt.Errorf("get flag pub-key: %w", err)
	}

	serverAddr, err := cmd.Flags().GetString("server")
	if err != nil {
		return RegisterConfig{}, fmt.Errorf("get flag server: %w", err)
	}

	cfg := RegisterConfig{
		Login:      trim(login),
		PubKeyPath: trim(pubKeyPath),
		ServerAddr: trim(serverAddr),
	}

	if cfg.Login == "" {
		return RegisterConfig{}, fmt.Errorf("login is required")
	}

	if cfg.PubKeyPath == "" {
		return RegisterConfig{}, fmt.Errorf("public key path is required")
	}

	if cfg.ServerAddr == "" {
		return RegisterConfig{}, fmt.Errorf("server address is required")
	}

	return cfg, nil
}

func newRegisterCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new passwordless account via SSH key",
		RunE: cli.withSSHAgent(func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadRegisterConfig(cmd)
			if err != nil {
				return err
			}

			sqlitePath, err := cli.DBPath()
			if err != nil {
				return fmt.Errorf("resolve sqlite path: %w", err)
			}

			keyBytes, err := os.ReadFile(cfg.PubKeyPath)
			if err != nil {
				return fmt.Errorf("read public key file: %w", err)
			}

			pubKey, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
			if err != nil {
				return fmt.Errorf("parse public key: %w", err)
			}

			fingerprint := sshagent.FingerprintSHA256(pubKey)

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Target SSH key fingerprint: %s\n", fingerprint)

			agentClient, err := sshagent.NewFromEnv()
			if err != nil {
				return fmt.Errorf("connect to ssh-agent: %w", err)
			}
			defer agentClient.Close()

			if _, err = agentClient.FindED25519ByFingerprint(fingerprint); err != nil {
				return fmt.Errorf("key must be loaded into ssh-agent (run 'ssh-add %s'): %w", cfg.PubKeyPath, err)
			}

			fmt.Fprintln(out, "Initiating secure registration protocol...")

			if err := grpc.ExecuteRegistrationFlow(
				cmd.Context(),
				cfg.ServerAddr,
				cfg.Login,
				pubKey,
				fingerprint,
				agentClient,
				sqlitePath,
			); err != nil {
				return fmt.Errorf("execute registration flow: %w", err)
			}

			fmt.Fprintf(out, "Success! User %q successfully registered and verified.\n", cfg.Login)

			return nil
		}),
	}

	cmd.Flags().String("login", "", "unique username/login")
	cmd.Flags().String("pub-key", "", "path to public SSH key (.pub)")
	cmd.Flags().String("server", "", "server address")

	_ = cmd.MarkFlagRequired("login")
	_ = cmd.MarkFlagRequired("pub-key")
	_ = cmd.MarkFlagRequired("server")

	return cmd
}
