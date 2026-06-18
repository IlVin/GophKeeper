package auth_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	"gophkeeper/internal/server/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestUnaryAuthInterceptor_PublicEndpointsPass(t *testing.T) {
	interceptor := auth.NewUnaryAuthInterceptor()
	ctx := context.Background()

	info := &grpc.UnaryServerInfo{FullMethod: "/gophkeeper.v1.Registration/RegisterBegin"}
	handler := func(ctx context.Context, req any) (any, error) {
		return "success", nil
	}

	resp, err := interceptor(ctx, nil, info, handler)
	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
}

func TestUnaryAuthInterceptor_MissingCredentialsError(t *testing.T) {
	interceptor := auth.NewUnaryAuthInterceptor()
	ctx := context.Background() // Пустой контекст без пира

	info := &grpc.UnaryServerInfo{FullMethod: "/gophkeeper.v1.Secrets/Sync"}
	handler := func(ctx context.Context, req any) (any, error) { return nil, nil }

	_, err := interceptor(ctx, nil, info, handler)
	assert.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUnaryAuthInterceptor_ValidSANURIPass(t *testing.T) {
	interceptor := auth.NewUnaryAuthInterceptor()

	// Конструируем mock-сертификат с правильной URI схемой urn:gophkeeper:file:<uuid>
	targetUUID := "11112222-3333-4444-5555-666677778888"
	parsedURL, err := url.Parse("urn:gophkeeper:file:" + targetUUID)
	require.NoError(t, err)

	mockCert := &x509.Certificate{
		URIs: []*url.URL{parsedURL},
	}

	// Помещаем mock-сертификат в TLS-структуры gRPC пира
	peerInfo := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{mockCert},
			},
		},
	}
	ctx := peer.NewContext(context.Background(), peerInfo)

	info := &grpc.UnaryServerInfo{FullMethod: "/gophkeeper.v1.Secrets/Sync"}
	handler := func(ctx context.Context, req any) (any, error) {
		// Проверяем, что ID контейнера успешно проброшен в контекст
		val := ctx.Value(auth.DeviceIDContextKey)
		assert.Equal(t, targetUUID, val)
		return "authenticated", nil
	}

	resp, err := interceptor(ctx, nil, info, handler)
	assert.NoError(t, err)
	assert.Equal(t, "authenticated", resp)
}
