package grpc

import (
	"crypto/tls"

	"gophkeeper/internal/server/config"

	// СОХРАНЕНО: Оставляем ваш путь генерации protobuf-файлов
	pb "gophkeeper/gen/go/gophkeeper/v1"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// NewGRPCServer принимает конфигурацию, TLS-конверт и пул соединений PostgreSQL.
func NewGRPCServer(cfg config.Config, tlsConfig *tls.Config, pool *pgxpool.Pool) *grpc.Server {
	creds := credentials.NewTLS(tlsConfig)
	opts := []grpc.ServerOption{grpc.Creds(creds)}

	server := grpc.NewServer(opts...)

	// Передаем флаг активности базы через (pool != nil)
	infoHandler := NewInfoHandler(cfg, func() bool { return pool != nil })
	pb.RegisterInfoServiceServer(server, infoHandler)

	regHandler := NewRegistrationHandler(cfg)
	pb.RegisterRegistrationServer(server, regHandler)

	// ДОБАВЛЕНО: Регистрация трехэтапного сервиса привязки устройств из спецификации v4.0
	// Предполагается, что DeviceAttachmentHandler реализован в файле attach_device.go
	attachHandler := NewDeviceAttachmentHandler(cfg)
	pb.RegisterDeviceAttachmentServer(server, attachHandler)

	return server
}
