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

const maxServerMsgSize = 32 * 1024 * 1024 // 32 MB

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
	slog.Info("Initializing core gRPC server network kernel for GophKeeper")

	creds := credentials.NewTLS(tlsConfig)

	// Формируем список опций сервера gRPC
	opts := []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.MaxRecvMsgSize(maxServerMsgSize),
		grpc.MaxSendMsgSize(maxServerMsgSize),
	}

	// Контролируем активность mTLS интерцептора авторизации устройств
	if authInterceptor != nil {
		slog.Debug("Registering unary mTLS interceptor for context-binding protection")
		opts = append(opts, grpc.UnaryInterceptor(authInterceptor.UnaryAuthInterceptor()))
	} else {
		slog.Warn("WARNING: gRPC server is being built WITHOUT mTLS authorization interceptor! Access is open to any valid certificates.")
	}

	server := grpc.NewServer(opts...)

	slog.Debug("Building and registering RegistrationHandler (Challenge State Machine)")
	regHandler := NewRegistrationHandler(cfg, pool)
	pb.RegisterRegistrationServer(server, regHandler)

	slog.Debug("Building and registering SyncHandler (LWW Replication)")
	syncHandler := NewSyncHandler(cfg, pool)
	pb.RegisterSyncServiceServer(server, syncHandler)

	slog.Info("gRPC server successfully configured and ready to handle network calls")
	return server
}
