package main

import (
	"fmt"
	"os"

	"gophkeeper/internal/server/commands"
	"gophkeeper/internal/server/config"
)

func main() {
	if err := run(); err != nil {
		// Выводим чистую критическую ошибку запуска в stderr для системных логов
		fmt.Fprintf(os.Stderr, "FATAL: server terminated with error: %v\n", err)
		os.Exit(1)
	}
}

// run инкапсулирует логику запуска и возвращает ошибку вместо неконтролируемого падения
func run() error {
	// 1. Инициализируем изолированный объект Viper для сбора конфигурации
	v := config.NewViper()

	// 2. Создаем фабрику команд сервера (Composition Root слоя CLI)
	// Внутри фабрики будет инициализирована структура CLI-контекста сервера
	serverCLI := commands.NewServerCLI(v)

	// 3. Гарантируем Graceful Shutdown и очистку памяти контейнера приложения (App)
	// при любом выходе из run() (ошибка валидации флагов, прерывание по сигналу, штатная остановка)
	defer func() {
		_ = serverCLI.Close()
	}()

	// 4. Собираем дерево Cobra команд сервера
	rootCmd, err := serverCLI.NewServerRootCommand()
	if err != nil {
		return fmt.Errorf("failed to initialize server CLI: %w", err)
	}

	// 5. Запускаем выполнение серверной Cobra-оболочки
	if err := rootCmd.Execute(); err != nil {
		return err
	}

	return nil
}
