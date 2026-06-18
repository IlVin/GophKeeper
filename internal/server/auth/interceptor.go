package auth

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type contextKey string

const (
	DeviceIDContextKey contextKey = "mtls_device_id"
	ExpectedURIPrefix             = "urn:gophkeeper:file:"
)

// NewUnaryAuthInterceptor создает gRPC перехватчик для проверки mTLS сертификатов устройств.
func NewUnaryAuthInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		// Разрешаем свободный доступ к challenge-методам регистрации и привязки
		if isPublicEndpoint(info.FullMethod) {
			return handler(ctx, req)
		}

		// Извлекаем TLS-информацию о подключенном пире
		p, ok := peer.FromContext(ctx)
		if !ok || p.AuthInfo == nil {
			return nil, status.Error(codes.Unauthenticated, "missing transport security credentials")
		}

		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
			return nil, status.Error(codes.Unauthenticated, "mTLS client certificate is required")
		}

		// Извлекаем первый (листовой) сертификат контейнера
		clientCert := tlsInfo.State.PeerCertificates[0]
		var deviceID string

		// Сканируем Subject Alternative Names (SAN) в поисках URI схемы v4.0
		for _, uri := range clientCert.URIs {
			uriStr := uri.String()
			if strings.HasPrefix(uriStr, ExpectedURIPrefix) {
				deviceID = strings.TrimPrefix(uriStr, ExpectedURIPrefix)
				break
			}
		}

		if deviceID == "" {
			return nil, status.Error(codes.Unauthenticated, "invalid client identity: missing or malformed container SAN URI")
		}

		// Помещаем верифицированный DeviceID в контекст запроса для бизнес-логики
		ctx = context.WithValue(ctx, DeviceIDContextKey, deviceID)

		return handler(ctx, req)
	}
}

func isPublicEndpoint(method string) bool {
	publicSuffixes := []string{
		"RegisterBegin",
		"RegisterFinish",
		"AttachDeviceBegin",
		"AttachDeviceAuth",
		"AttachDeviceFinish",
		"GetInfo",
	}
	for _, suffix := range publicSuffixes {
		if strings.HasSuffix(method, suffix) {
			return true
		}
	}
	return false
}
