package main

import (
	"fmt"
	"os"

	"gophkeeper/internal/client/commands"
	"gophkeeper/internal/client/config"
)

func main() {
	if err := run(); err != nil {
		// Вместо log.Fatal выводим чистую ошибку в stderr для UX
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// run инкапсулирует инициализацию и запуск CLI для обеспечения тестируемости
func run() error {
	v, err := config.NewViper()
	if err != nil {
		return fmt.Errorf("create config loader: %w", err)
	}

	// Инициализируем наш CLI слой
	cli := commands.NewCLI(v)

	// Гарантируем, что при любом выходе из run() (паника, ошибка, успех)
	// отработает очистка памяти runtime-контейнера App, если он успел создаться.
	defer func() {
		_ = cli.Close()
	}()

	cmd, err := cli.NewRootCommand()
	if err != nil {
		return fmt.Errorf("failed to initialize client CLI: %w", err)
	}

	// Передаем контекст выполнения, чтобы корректно работали прерывания (Ctrl+C)
	if err := cmd.Execute(); err != nil {
		// Возвращаем саму ошибку, чтобы CLI-команды могли сами форматировать UX
		return err
	}

	return nil
}
