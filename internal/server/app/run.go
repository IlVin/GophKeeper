// Package app координирует рантайм-контейнер ресурсов серверной части приложения,
// управляя процессами инициализации, сетевого вещания и безопасной остановки.
package app

import (
	"context"
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
		slog.Error("Server startup rejected: gRPC server or Listener not initialized")
		return errors.New("grpc server or listener not initialized")
	}

	slog.Info("Cloud GophKeeper gRPC server successfully started and broadcasting",
		slog.String("addr", a.Listener.Addr().String()),
	)

	if err := a.GRPCServer.Serve(a.Listener); err != nil && !errors.Is(err, errors.New("grpc: the server has been stopped")) {
		slog.ErrorContext(context.Background(), "Critical gRPC network broadcast failure",
			slog.Any("error", err),
		)
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
	slog.Info("Initiating server graceful shutdown procedure")

	if a.GRPCServer != nil {
		// Защитный ИБ-барьер: предотвращаем вечное зависание стоппера из-за «мертвых» клиентских стримов
		shutdownTimeout := 10 * time.Second
		done := make(chan struct{})

		slog.Debug("Waiting for active client sync RPC calls to complete",
			slog.Duration("timeout", shutdownTimeout),
		)
		go func() {
			a.GRPCServer.GracefulStop()
			close(done)
		}()

		select {
		case <-done:
			slog.Debug("All active client gRPC sessions completed gracefully")
		case <-time.After(shutdownTimeout):
			slog.Warn("Graceful Shutdown timeout exceeded! Forcing hard server socket stop.")
			a.GRPCServer.Stop() // Жестко рвем зависшие соединения для высвобождения ресурсов
		}
	}

	// Освобождаем сетевые порты Let's Encrypt ACME с проверкой ошибок
	if a.AcmeListener != nil {
		slog.Debug("Closing auxiliary Let.s Encrypt ACME socket")
		if closeErr := a.AcmeListener.Close(); closeErr != nil {
			slog.ErrorContext(context.Background(), "ACME Listener socket destructor failed during resource finalization",
				slog.Any("error", closeErr),
			)
		}
	}

	// Финализируем пул СУБД PostgreSQL, возвращая коннекты операционной системе
	if a.Pool != nil {
		slog.Debug("Closing PostgreSQL connection pool")
		a.Pool.Close()
	}

	slog.Info("Graceful Shutdown procedure completed successfully, all resource pools cleared")
	return nil
}
