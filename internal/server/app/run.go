package app

import (
	"fmt"
)

func (a *App) Run() error {
	if a.GRPCServer == nil || a.Listener == nil {
		return fmt.Errorf("grpc server or listener not initialized")
	}

	if err := a.GRPCServer.Serve(a.Listener); err != nil {
		return fmt.Errorf("grpc server serve: %w", err)
	}

	return nil
}

func (a *App) Shutdown() error {
	if a.GRPCServer != nil {
		a.GRPCServer.GracefulStop()
	}
	if a.AcmeListener != nil {
		_ = a.AcmeListener.Close()
	}
	if a.Pool != nil {
		a.Pool.Close()
	}
	return nil
}
