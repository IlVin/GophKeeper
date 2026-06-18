package main

import (
	"fmt"
	"log"

	"gophkeeper/internal/client/commands"
	"gophkeeper/internal/client/config"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// run инкапсулирует инициализацию и запуск CLI для обеспечения тестируемости
func run() error {
	v := config.NewViper()

	cmd, err := commands.NewRootCommand(v)
	if err != nil {
		return fmt.Errorf("failed to initialize client CLI: %w", err)
	}

	if err := cmd.Execute(); err != nil {
		return fmt.Errorf("command execution failed: %w", err)
	}

	return nil
}
