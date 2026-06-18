package app_test

import (
	"context"
	"net"
	"testing"

	"gophkeeper/internal/server/app"
	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func TestAppFromContext_SuccessAndFailure(t *testing.T) {
	ctx := context.Background()
	_, err := app.AppFromContext(ctx)
	assert.ErrorContains(t, err, "server app is missing in context")

	var cfg config.Config
	mockListener := &net.TCPListener{}
	mockgRPC := &grpc.Server{}

	application := app.NewApp(cfg, mockListener, mockgRPC, nil)
	ctx = app.WithApp(ctx, application)

	extracted, err := app.AppFromContext(ctx)
	assert.NoError(t, err)
	assert.Equal(t, application, extracted)
}
