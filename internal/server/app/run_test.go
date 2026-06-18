package app_test

import (
	"testing"

	"gophkeeper/internal/server/app"
	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
)

func TestApp_RunUninitializedError(t *testing.T) {
	var cfg config.Config
	application := app.NewApp(cfg, nil, nil, nil)

	err := application.Run()
	assert.ErrorContains(t, err, "grpc server or listener not initialized")
}

func TestApp_ShutdownGracefulNoPanic(t *testing.T) {
	var cfg config.Config
	application := app.NewApp(cfg, nil, nil, nil)

	err := application.Shutdown()
	assert.NoError(t, err)
}
