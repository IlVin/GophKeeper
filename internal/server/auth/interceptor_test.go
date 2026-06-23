package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// TestNewAuthInterceptor_Constructor_Success проверяет штатное конструирование объекта интерцептора.
func TestNewAuthInterceptor_Constructor_Success(t *testing.T) {
	interceptor, err := NewAuthInterceptor(nil)
	require.NoError(t, err)
	require.NotNil(t, interceptor)

	unaryFunc := interceptor.UnaryAuthInterceptor()
	assert.NotNil(t, unaryFunc)
}

// TestAuthInterceptor_PublicEndpoints_ShouldBypass проверяет, что публичные методы
// из белого списка успешно проходят сквозь интерцептор в анонимном TLS-режиме (без сертификата).
func TestAuthInterceptor_PublicEndpoints_ShouldBypass(t *testing.T) {
	interceptor, err := NewAuthInterceptor(nil)
	require.NoError(t, err)

	unaryFunc := interceptor.UnaryAuthInterceptor()
	ctx := context.Background()

	info := &grpc.UnaryServerInfo{
		FullMethod: "/gophkeeper.v1.Registration/RegisterBegin",
	}

	dummyHandler := func(ctx context.Context, req any) (any, error) {
		return "allowed_anonymous", nil
	}

	res, err := unaryFunc(ctx, nil, info, dummyHandler)
	require.NoError(t, err)
	assert.Equal(t, "allowed_anonymous", res)
}

// TestAuthInterceptor_ProtectedEndpoints_FailsIfNoCertificate проверяет ИБ-барьер:
// если защищенный метод вызывается без mTLS-сертификата (TLS-Bypass), интерцептор обязан вернуть Unauthenticated.
func TestAuthInterceptor_ProtectedEndpoints_FailsIfNoCertificate(t *testing.T) {
	interceptor, err := NewAuthInterceptor(nil)
	require.NoError(t, err)

	unaryFunc := interceptor.UnaryAuthInterceptor()

	// Имитируем контекст gRPC-пира, у которого есть TLS-подключение, но НЕТ PeerCertificates (атака TLS-Bypass)
	peerInfo := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{}, // Пустой слайс паспорта
			},
		},
	}
	ctx := peer.NewContext(context.Background(), peerInfo)

	info := &grpc.UnaryServerInfo{
		FullMethod: "/gophkeeper.v1.SyncService/SyncCheck",
	}

	dummyHandler := func(ctx context.Context, req any) (any, error) {
		return "should_not_be_reached", nil
	}

	res, err := unaryFunc(ctx, nil, info, dummyHandler)

	assert.Nil(t, res)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code(), "Интерцептор обязан вернуть код Unauthenticated для защиты от TLS-Bypass")
	assert.Contains(t, st.Message(), "mutual TLS authentication is strictly required")
}
