// Package grpc предоставляет реализации gRPC-хендлеров, фабрик сборки серверов
// и интерцепторов для серверной части распределенной экосистемы GophKeeper.
package grpc

import (
	"crypto/tls"
	"log/slog"

	"gophkeeper/internal/server/auth"
	"gophkeeper/internal/server/config"

	// Канонический путь импорта обновленных protobuf-файлов
	pb "gophkeeper/gen/go/gophkeeper/v1"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// NewGRPCServer конструирует и настраивает экземпляр gRPC-сервера GophKeeper.
//
// Функция инкапсулирует в себе внедрение пула соединений PostgreSQL,
// привязывает TLS-контекст шифрования каналов и регистрирует унарный
// интерцептор ИБ-проверки mTLS паспортов контейнеров.
func NewGRPCServer(
	cfg config.Config,
	tlsConfig *tls.Config,
	pool *pgxpool.Pool,
	authInterceptor *auth.AuthInterceptor,
) *grpc.Server {
	slog.Info("Инициализация базового сетевого ядра gRPC сервера GophKeeper")

	creds := credentials.NewTLS(tlsConfig)

	// Формируем список опций сервера gRPC
	opts := []grpc.ServerOption{
		grpc.Creds(creds),
	}

	// Контролируем активность mTLS интерцептора авторизации устройств
	if authInterceptor != nil {
		slog.Debug("Регистрация унарного mTLS интерцептора защиты context-binding")
		opts = append(opts, grpc.UnaryInterceptor(authInterceptor.UnaryAuthInterceptor()))
	} else {
		slog.Warn("ВНИМАНИЕ: gRPC сервер собирается БЕЗ интерцептора mTLS авторизации! Доступ открыт для любых валидных сертификатов.")
	}

	server := grpc.NewServer(opts...)

	slog.Debug("Сборка и регистрация хендлера RegistrationHandler (Challenge State Machine)")
	regHandler := NewRegistrationHandler(cfg, pool)
	pb.RegisterRegistrationServer(server, regHandler)

	slog.Debug("Сборка и регистрация хендлера SyncHandler (LWW Репликация)")
	syncHandler := NewSyncHandler(cfg, pool)
	pb.RegisterSyncServiceServer(server, syncHandler)

	slog.Info("gRPC сервер успешно сконфигурирован и готов к обработке сетевых вызовов")
	return server
}
