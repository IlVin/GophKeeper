// Package app координирует рантайм-контейнер ресурсов серверной части приложения,
// управляя процессами инициализации, сетевого вещания и безопасной остановки.
package app

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Run переводит инициализированный gRPC-сервер в режим блокирующего вещания.
//
// Функция открывает сетевой порт Listener и начинает принимать входящие TLS 1.3
// и mTLS соединения от оффлайн-клиентов менеджера паролей GophKeeper.
func (a *App) Run() error {
	if a.GRPCServer == nil || a.Listener == nil {
		slog.Error("Запуск сервера отклонен: gRPC сервер или сетевой Listener не инициализированы")
		return errors.New("grpc server or listener not initialized")
	}

	slog.Info("Облачный gRPC-сервер GophKeeper успешно запущен и начинает вещание",
		"addr", a.Listener.Addr().String())

	if err := a.GRPCServer.Serve(a.Listener); err != nil && !errors.Is(err, errors.New("grpc: the server has been stopped")) {
		slog.Error("Критический сбой сетевого вещания gRPC службы", "error", err)
		return fmt.Errorf("grpc server serve collapsed: %w", err)
	}

	return nil
}

// Shutdown выполняет безопасную, поэтапную финализацию всех системных ресурсов (Graceful Shutdown).
//
// Метод останавливает сетевой прием, дает активным горутинам синхронизации до 10 секунд
// на завершение ACID-транзакций, закрывает порты Let's Encrypt и освобождает пул PostgreSQL,
// полностью предотвращая утечки дескрипторов файлов и зомби-процессы в операционной системе.
func (a *App) Shutdown() error {
	slog.Info("Инициирована процедура безопасной остановки сервера (Graceful Shutdown)")

	if a.GRPCServer != nil {
		// Защитный ИБ-барьер: предотвращаем вечное зависание стоппера из-за «мертвых» клиентских стримов
		shutdownTimeout := 10 * time.Second
		done := make(chan struct{})

		slog.Debug("Ожидание завершения активных RPC-вызовов синхронизации клиентов", "timeout", shutdownTimeout)
		go func() {
			a.GRPCServer.GracefulStop()
			close(done)
		}()

		select {
		case <-done:
			slog.Debug("Все активные клиентские gRPC сессии завершены штатно")
		case <-time.After(shutdownTimeout):
			slog.Warn("Таймаут Graceful Shutdown превышен! Запущена принудительная жесткая остановка сокетов сервера.")
			a.GRPCServer.Stop() // Жестко рвем зависшие соединения для высвобождения ресурсов
		}
	}

	// Освобождаем сетевые порты Let's Encrypt ACME с проверкой ошибок
	if a.AcmeListener != nil {
		slog.Debug("Закрытие вспомогательного ACME сокета Let's Encrypt")
		if closeErr := a.AcmeListener.Close(); closeErr != nil {
			slog.Error("Сбой деструктора сокета ACME Listener при финализации ресурсов", "error", closeErr)
		}
	}

	// Финализируем пул СУБД PostgreSQL, возвращая коннекты операционной системе
	if a.Pool != nil {
		slog.Debug("Закрытие пула соединений PostgreSQL СУБД")
		a.Pool.Close()
	}

	slog.Info("Процедура Graceful Shutdown успешно завершена, все пулы ресурсов очищены")
	return nil
}
