// Package main является главной точкой входа для запуска облачного gRPC-сервера
// распределенной экосистемы хранения зашифрованных контейнеров GophKeeper.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"gophkeeper/internal/server/commands"
	"gophkeeper/internal/server/config"
)

func main() {
	// Инициируем сквозной запуск сервера с перехватом критических исключений
	if err := run(); err != nil {
		// Фиксируем ИБ-инцидент падения сервера в системный логгер
		slog.ErrorContext(context.Background(), "Critical runtime failure: server terminated abnormally",
			slog.Any("error", err),
		)

		// Дублируем чистый трейс в stderr для системных демонов ОС (systemd/docker logs)
		fmt.Fprintf(os.Stderr, "FATAL: server terminated with error: %v\n", err)
		os.Exit(1)
	}
}

// run координирует инициализацию CLI-оболочки сервера, разворачивание дерева
// команд Cobra и гарантирует Graceful Shutdown всех внутренних пулов соединений.
func run() error {
	// 1. Инициализируем изолированный объект Viper для сбора конфигурации
	v := config.NewViper()

	// 2. Создаем фабрику команд сервера (Composition Root слоя CLI)
	serverCLI := commands.NewServerCLI(v)

	// 3. Гарантируем Graceful Shutdown и очистку памяти пулов при любом выходе из run()
	defer func() {
		if closeErr := serverCLI.Close(); closeErr != nil {
			// Явно перехватываем ошибку закрытия ресурсов для исключения зомби-дескрипторов в ОС
			slog.ErrorContext(context.Background(), "Error finalizing server resources during Graceful Shutdown",
				slog.Any("error", closeErr),
			)
		}
	}()

	// 4. Собираем дерево Cobra команд сервера
	rootCmd, err := serverCLI.NewServerRootCommand()
	if err != nil {
		return fmt.Errorf("failed to initialize server CLI structure: %w", err)
	}

	// 5. Запускаем выполнение серверной Cobra-оболочки
	if err := rootCmd.Execute(); err != nil {
		return fmt.Errorf("server command execution failed: %w", err)
	}

	return nil
}
