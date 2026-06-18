package grpc

import (
	"context"
	"net"
	"testing"

	pb "gophkeeper/gen/go/gophkeeper/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// mockInfoServer реализует сгенерированный protoc gRPC интерфейс для тестов
type mockInfoServer struct {
	pb.UnimplementedInfoServiceServer
	shouldFail bool
}

func (s *mockInfoServer) GetInfo(ctx context.Context, req *pb.InfoRequest) (*pb.InfoResponse, error) {
	if s.shouldFail {
		return nil, status.Error(codes.Internal, "mock database failure")
	}
	return &pb.InfoResponse{
		ServerVersion:     "v1.0.0-test",
		Environment:       "test-bufconn",
		DatabaseConnected: true,
	}, nil
}

func TestFetchServerInfo_ExecutionFlows(t *testing.T) {
	t.Parallel()

	// Инициализируем виртуальный буферизованный сетевой слушатель на 1 Мб
	bufferSize := 1024 * 1024
	lis := bufconn.Listen(bufferSize)

	// Поднимаем тестовый gRPC сервер в фоне
	srv := grpc.NewServer()
	mockServer := &mockInfoServer{}
	pb.RegisterInfoServiceServer(srv, mockServer)

	go func() {
		_ = srv.Serve(lis)
	}()
	defer srv.Stop()

	t.Run("successful rpc pipeline", func(t *testing.T) {
		mockServer.shouldFail = false

		// Переопределяем стандартный dialer gRPC клиента на наш виртуальный буфер
		dialer := func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}

		conn, err := grpc.NewClient("passthrough://bufconn",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()), // Отключаем TLS внутри буфера
		)
		require.NoError(t, err)
		defer conn.Close()

		client := pb.NewInfoServiceClient(conn)
		resp, err := client.GetInfo(context.Background(), &pb.InfoRequest{})

		require.NoError(t, err)
		assert.Equal(t, "v1.0.0-test", resp.GetServerVersion())
		assert.True(t, resp.GetDatabaseConnected())
	})

	t.Run("server returns functional status error", func(t *testing.T) {
		mockServer.shouldFail = true

		dialer := func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}

		conn, err := grpc.NewClient("passthrough://bufconn",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		defer conn.Close()

		client := pb.NewInfoServiceClient(conn)
		_, err = client.GetInfo(context.Background(), &pb.InfoRequest{})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}
