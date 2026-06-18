package app

import (
	"context"
	"fmt"
	"net"

	"gophkeeper/internal/server/config"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
)

type App struct {
	Config       config.Config
	Listener     net.Listener
	GRPCServer   *grpc.Server
	Pool         *pgxpool.Pool
	AcmeListener net.Listener
}

type contextKey string

const appContextKey contextKey = "server_app"

// NewApp конструирует контейнер приложения.
func NewApp(cfg config.Config, listener net.Listener, grpcServer *grpc.Server, acmeListener net.Listener) *App {
	return &App{
		Config:       cfg,
		Listener:     listener,
		GRPCServer:   grpcServer,
		AcmeListener: acmeListener,
	}
}

func WithApp(ctx context.Context, application *App) context.Context {
	return context.WithValue(ctx, appContextKey, application)
}

func AppFromContext(ctx context.Context) (*App, error) {
	application, ok := ctx.Value(appContextKey).(*App)
	if !ok || application == nil {
		return nil, fmt.Errorf("server app is missing in context")
	}
	return application, nil
}
