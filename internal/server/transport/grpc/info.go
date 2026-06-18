package grpc

import (
	"context"

	pb "gophkeeper/gen/go/gophkeeper/v1"
	"gophkeeper/internal/server/config"
)

type InfoHandler struct {
	pb.UnimplementedInfoServiceServer
	cfg      config.Config
	isDbOpen func() bool
}

// NewInfoHandler конструирует обработчик для отладки связи
func NewInfoHandler(cfg config.Config, isDbOpen func() bool) *InfoHandler {
	return &InfoHandler{
		cfg:      cfg,
		isDbOpen: isDbOpen,
	}
}

func (h *InfoHandler) GetInfo(ctx context.Context, req *pb.InfoRequest) (*pb.InfoResponse, error) {
	// Возвращаем тестовые параметры среды
	return &pb.InfoResponse{
		ServerVersion:     "v0.1.0-alpha",
		Environment:       "development-local-tls",
		DatabaseConnected: h.isDbOpen(),
	}, nil
}
