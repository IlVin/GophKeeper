package grpc

import (
	"crypto/tls"

	"gophkeeper/internal/server/config"
	// СОХРАНЕНО: Оставляем ваш путь генерации protobuf-файлов
	pb "gophkeeper/gen/go/gophkeeper/v1"
	"gophkeeper/internal/server/auth"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// NewGRPCServer принимает конфигурацию, TLS-конверт, пул PostgreSQL и интерцептор безопасности (Инвариант mTLS)
func NewGRPCServer(
	cfg config.Config,
	tlsConfig *tls.Config,
	pool *pgxpool.Pool,
	authInterceptor *auth.AuthInterceptor, // ДОБАВЛЕНО
) *grpc.Server {
	creds := credentials.NewTLS(tlsConfig)

	// Формируем список опций сервера gRPC
	opts := []grpc.ServerOption{
		grpc.Creds(creds),
	}

	// ДОБАВЛЕНО: Регистрируем унарный интерцептор проверки mTLS сертификатов контейнеров
	if authInterceptor != nil {
		opts = append(opts, grpc.UnaryInterceptor(authInterceptor.UnaryAuthInterceptor()))
	}

	server := grpc.NewServer(opts...)

	// ИСПРАВЛЕНО: Передаем pool соединений PostgreSQL для работы Challenge State Machine
	regHandler := NewRegistrationHandler(cfg, pool)
	pb.RegisterRegistrationServer(server, regHandler)

	syncHandler := NewSyncHandler(cfg, pool)
	pb.RegisterSyncServiceServer(server, syncHandler)

	return server
}
