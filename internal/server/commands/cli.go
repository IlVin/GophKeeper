package commands

import (
	"context"
	"fmt"
	"sync"

	serverapp "gophkeeper/internal/server/app"

	"github.com/spf13/viper"
)

type ServerCLI struct {
	v *viper.Viper

	appMu  sync.Mutex
	app    *serverapp.App
	appErr error
}

func NewServerCLI(v *viper.Viper) *ServerCLI {
	return &ServerCLI{v: v}
}

// App лениво инициализирует и бутстрапит серверный контейнер при необходимости
func (c *ServerCLI) App(ctx context.Context) (*serverapp.App, error) {
	c.appMu.Lock()
	defer c.appMu.Unlock()

	if c.app != nil {
		return c.app, nil
	}

	// Вызываем бутстрап сервера строго внутри Composition Root
	_, app, err := serverapp.Bootstrap(ctx, c.v)
	if err != nil {
		c.appErr = fmt.Errorf("server initialization failed: %w", err)
		return nil, c.appErr
	}

	c.app = app
	c.appErr = nil
	return c.app, nil
}

// Close гарантирует Graceful Shutdown всех пулов соединений фонового сервера
func (c *ServerCLI) Close() error {
	c.appMu.Lock()
	defer c.appMu.Unlock()

	if c.app == nil {
		return nil
	}

	// Вызываем штатную остановку gRPC листенеров и пула pgxpool
	err := c.app.Shutdown()
	c.app = nil
	c.appErr = nil
	return err
}
