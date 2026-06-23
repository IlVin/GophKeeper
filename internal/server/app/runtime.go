// Package app координирует рантайм-контейнер ресурсов серверной части приложения,
// управляя процессами инициализации, сетевого вещания и безопасной остановки.
package app

import (
	"context"
	"errors"
	"net"

	"gophkeeper/internal/server/config"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
)

// App инкапсулирует в себе все долговечные глобальные ресурсы, пулы соединений
// и сетевые интерфейсы запущенного инстанса сервера GophKeeper.
type App struct {
	Config       config.Config
	Listener     net.Listener
	GRPCServer   *grpc.Server
	Pool         *pgxpool.Pool
	AcmeListener net.Listener
}

type contextKey string

const appContextKey contextKey = "server_app"

// NewApp конструирует и полностью наполняет контейнер ресурсов приложения App.
//
// Добавлено принудительное внедрение зависимости пула pgxpool.Pool
// для обеспечения бесшовного каскадного освобождения дескрипторов СУБД.
func NewApp(
	cfg config.Config,
	listener net.Listener,
	grpcServer *grpc.Server,
	pool *pgxpool.Pool,
	acmeListener net.Listener,
) *App {
	return &App{
		Config:       cfg,
		Listener:     listener,
		GRPCServer:   grpcServer,
		Pool:         pool,
		AcmeListener: acmeListener,
	}
}

// WithApp упаковывает указатель на контейнер App в изолированный контекст горутины.
func WithApp(ctx context.Context, application *App) context.Context {
	return context.WithValue(ctx, appContextKey, application)
}

// AppFromContext безопасно извлекает и валидирует объект App из контекста горутины.
//
// В случае отсутствия или повреждения структуры возвращает ошибку на английском языке.
func AppFromContext(ctx context.Context) (*App, error) {
	application, ok := ctx.Value(appContextKey).(*App)
	if !ok || application == nil {
		return nil, errors.New("server app runtime context container is missing or corrupted")
	}
	return application, nil
}
