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

// TestSyncHandler_SyncCheck_FailsIfUnauthenticated проверяет срабатывание барьера
// mTLS-авторизации, если rpc-метод вызван без контекстных метаданных идентификации устройства.
func TestSyncHandler_SyncCheck_FailsIfUnauthenticated(t *testing.T) {
	cfg := config.Config{}

	// Конструируем хендлер с nil пулом (тест должен упасть на этапе проверки контекста)
	handler := NewSyncHandler(cfg, nil)
	ctx := context.Background() // Чистый контекст без DeviceID

	req := &pb.SyncCheckRequest{
		LocalVersions: nil,
	}

	resp, err := handler.SyncCheck(ctx, req)

	assert.Nil(t, resp)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code(), "Код ошибки обязан соответствовать Unauthenticated")
	assert.Contains(t, st.Message(), "mTLS identity context missing")
}
