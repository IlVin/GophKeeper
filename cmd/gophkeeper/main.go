// Package main является точкой входа (Composition Root) для клиентского CLI-приложения GophKeeper.
//
// Пакет отвечает за первичный перехват системных сигналов, настройку двухэтапного
// логирования через slog, инициализацию конфигурационного движка Viper, сборку
// дерева команд Cobra и безопасную очистку ресурсов при завершении работы.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"gophkeeper/internal/client/commands"
	"gophkeeper/internal/client/config"
)

// main является системной точкой входа рантайма Go.
// Она делегирует управление функции run и обрабатывает критические ошибки на выходе.
func main() {
	if err := run(); err != nil {
		// Пользователю в терминал отдается только чистый UX-текст ошибки без системного шума
		fmt.Fprintf(os.Stderr, "Ошибка: %v\n", err)
		os.Exit(1)
	}
}

// run инкапсулирует весь жизненный цикл инициализации CLI-приложения.
//
// Функция настраивает контекст отмены ОС, безопасный барьер перехвата паник,
// двухэтапное логирование в файл, чтение конфигурации и запуск командного слоя.
// Возвращает именованную ошибку для предотвращения маскирования сбоев в defer.
func run() (err error) {
	// Контекст прерываний (Ctrl+C, SIGTERM) для корректной отмены сетевых gRPC и СУБД операций
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ЭТАП 1 LOGGING: Раннее безопасное логирование по дефолтному XDG-пути.
	// Гарантирует, что любые сбои до чтения файла конфигурации запишутся в файл, а не в консоль.
	defaultLogPath := config.DefaultLogPath()
	earlyFile, err := configureGlobalSlog(defaultLogPath, "debug", "text")
	if err != nil {
		return fmt.Errorf("инициализация раннего логгера: %w", err)
	}
	var activeLogFile *os.File = earlyFile
	defer func() {
		if activeLogFile != nil {
			_ = activeLogFile.Close()
		}
	}()

	slog.Debug("Ранний логгер успешно инициализирован")

	// Инициализация загрузчика конфигурации Viper
	v, err := config.NewViper()
	if err != nil {
		slog.Error("не удалось создать загрузчик конфигурации", "error", err)
		return fmt.Errorf("создание конфигуратора: %w", err)
	}

	if err := config.ReadConfigFile(v); err != nil {
		slog.Error("не удалось прочитать файл конфигурации", "error", err)
		return fmt.Errorf("чтение конфигурации: %w", err)
	}

	// ЭТАП 2 LOGGING: Динамический пересчет параметров логирования на основе настроек пользователя.
	customLogPath := strings.TrimSpace(v.GetString("logging.log_file"))
	customLevel := v.GetString("logging.level")
	customFormat := v.GetString("logging.format")

	// Если пользователь переопределил путь или параметры — атомарно переключаем логгер
	if customLogPath != defaultLogPath || customLevel != "debug" || customFormat != "text" {
		slog.Debug("Переконфигурация логгера под пользовательские настройки", "new_path", customLogPath)

		newFile, err := configureGlobalSlog(customLogPath, customLevel, customFormat)
		if err != nil {
			slog.Error("не удалось применить пользовательские настройки логирования, оставлен дефолтный логгер", "error", err)
		} else {
			if earlyFile != nil {
				_ = earlyFile.Close()
			}
			activeLogFile = newFile
			slog.Info("Логгер успешно переключен на пользовательский файл конфигурации")
		}
	}

	// Сборка CLI слоя приложения
	cli := commands.NewCLI(v)

	// Защитный барьер от непредвиденных паник рантайма (предотвращает утечку stack-trace в консоль)
	defer func() {
		if r := recover(); r != nil {
			slog.Error("перехвачена критическая паника приложения", slog.Any("panic_info", r))
			err = errors.New("произошла критическая внутренняя ошибка")
		}
	}()

	// Контроль освобождения дескрипторов ресурсов и соединений SQLite СУБД
	defer func() {
		if closeErr := cli.Close(); closeErr != nil {
			slog.Error("не удалось безопасно закрыть ресурсы приложения", "error", closeErr)
			if err == nil {
				err = fmt.Errorf("закрытие ресурсов: %w", closeErr)
			}
		}
	}()

	cmd, err := cli.NewRootCommand()
	if err != nil {
		slog.Error("не удалось собрать дерево CLI команд", "error", err)
		return fmt.Errorf("инициализация CLI: %w", err)
	}

	// Запуск исполнения дерева команд с передачей контекста отмены сигналов ОС
	if executeErr := cmd.ExecuteContext(ctx); executeErr != nil {
		slog.Error("исполнение CLI команды завершилось ошибкой", "error", executeErr)
		return executeErr
	}

	slog.Info("Работа CLI движка GophKeeper успешно завершена")
	return nil
}

// configureGlobalSlog подготавливает файловую структуру и переключает стандартный логгер slog.
//
// Принимает абсолютный путь к файлу, строковое представление уровня (debug, info, warn, error)
// и формат (json, text). Принудительно выставляет права доступа 0700 на папки и 0600 на файл лога.
func configureGlobalSlog(path, levelStr, formatStr string) (*os.File, error) {
	if path == "" {
		return nil, errors.New("путь к лог-файлу не может быть пустым")
	}

	logDir := filepath.Dir(path)
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, fmt.Errorf("создание директории логов %q: %w", logDir, err)
	}

	// Открытие в режиме O_APPEND для сохранения истории запусков утилиты
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("открытие лог-файла %q: %w", path, err)
	}

	logLevel := slog.LevelDebug
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}

	var handler slog.Handler
	if strings.ToLower(strings.TrimSpace(formatStr)) == "json" {
		handler = slog.NewJSONHandler(f, &slog.HandlerOptions{Level: logLevel})
	} else {
		handler = slog.NewTextHandler(f, &slog.HandlerOptions{Level: logLevel})
	}

	slog.SetDefault(slog.New(handler))
	return f, nil
}
