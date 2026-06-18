package grpc

import (
	"context"
	"testing"

	"gophkeeper/internal/server/config"

	pb "gophkeeper/gen/go/gophkeeper/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInfoHandler_GetInfo_Success(t *testing.T) {
	var cfg config.Config
	dbOpenMock := func() bool { return true }

	handler := NewInfoHandler(cfg, dbOpenMock)
	req := &pb.InfoRequest{}

	resp, err := handler.GetInfo(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "v0.1.0-alpha", resp.GetServerVersion())
	assert.Equal(t, "development-local-tls", resp.GetEnvironment())
	assert.True(t, resp.GetDatabaseConnected())
}
