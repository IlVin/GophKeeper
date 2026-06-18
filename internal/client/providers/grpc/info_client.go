package grpc

import (
	"context"
	"fmt"
	"time"

	pb "gophkeeper/gen/go/gophkeeper/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// FetchServerInfo устанавливает чистое TLS соединение с сервером и запрашивает INFO
func FetchServerInfo(ctx context.Context, serverAddr string) (*pb.InfoResponse, error) {
	// 1. Загружаем TLS-конфигурацию бутстрапа (использует встроенный ServerCA)
	tlsConfig, err := ConfigForBootstrap()
	if err != nil {
		return nil, fmt.Errorf("failed to load bootstrap tls config: %w", err)
	}

	conn, err := grpc.NewClient(serverAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client over TLS: %w", err)
	}
	defer conn.Close()

	// 3. Задаем жесткий таймаут на выполнение самого сетевого RPC запроса
	rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// 4. Выполняем удаленный вызов процедуры
	client := pb.NewInfoServiceClient(conn)
	resp, err := client.GetInfo(rpcCtx, &pb.InfoRequest{})
	if err != nil {
		return nil, fmt.Errorf("rpc GetInfo failed: %w", err)
	}

	return resp, nil
}
