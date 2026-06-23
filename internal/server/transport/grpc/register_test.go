package grpc

import (
	"context"
	"testing"

	pb "gophkeeper/gen/go/gophkeeper/v1"
	"gophkeeper/internal/server/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRegistrationHandler_RegisterBegin_FailsIfEmptyKey проверяет fail-fast барьер
// валидации gRPC-контроллера при отправке пустого массива байт публичного ключа.
func TestRegistrationHandler_RegisterBegin_FailsIfEmptyKey(t *testing.T) {
	cfg := config.Config{}

	// Конструируем хендлер с nil пулом (тест должен упасть ДО обращения к базе данных)
	handler := NewRegistrationHandler(cfg, nil)
	ctx := context.Background()

	req := &pb.RegisterBeginRequest{
		SshPublicKey: []byte(""), // Пустой ключ
	}

	resp, err := handler.RegisterBegin(ctx, req)

	assert.Nil(t, resp)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code(), "Код ошибки обязан соответствовать InvalidArgument")
	assert.Equal(t, "ssh public key cannot be empty", st.Message())
}
