package main

import (
	"fmt"
	"log"

	"gophkeeper/internal/server/commands"
	"gophkeeper/internal/server/config"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("server terminated with error: %v", err)
	}
}

// run инкапсулирует логику запуска и возвращает ошибку вместо падения бинарника
func run() error {
	v := config.NewViper()

	rootCmd, err := commands.NewServerRootCommand(v)
	if err != nil {
		return fmt.Errorf("failed to initialize server CLI: %w", err)
	}

	if err := rootCmd.Execute(); err != nil {
		return fmt.Errorf("command execution failed: %w", err)
	}

	return nil
}
