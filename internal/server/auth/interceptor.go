package auth

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"gophkeeper/internal/shared/certs"

	"github.com/jackc/pgx/v5/pgxpool"
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

type AuthInterceptor struct {
	deviceCAPool *x509.CertPool
	pool         *pgxpool.Pool
}

func NewAuthInterceptor(dbPool *pgxpool.Pool) (*AuthInterceptor, error) {
	devicePool, err := certs.LoadDeviceCAPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load embedded device CA: %w", err)
	}
	return &AuthInterceptor{deviceCAPool: devicePool, pool: dbPool}, nil
}

// UnaryAuthInterceptor — шлюз безопасности для работы TLS и mTLS на одном сетевом порту.
func (in *AuthInterceptor) UnaryAuthInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		// 1. White List: Разрешаем анонимный TLS-доступ к методам регистрации
		if isPublicEndpoint(info.FullMethod) {
			slog.Debug("Bypassing mTLS check for public registration endpoint",
				slog.String("method", info.FullMethod),
			)
			return handler(ctx, req)
		}

		// 2. ИБ-БАРИЕР ДЛЯ ЗАКРЫТЫХ МЕТОДОВ (Sync Check, Pull, Push)
		// Если метод закрытый, наличие клиентского mTLS-сертификата КАТЕГОРИЧЕСКИ ОБЯЗАТЕЛЬНО
		p, ok := peer.FromContext(ctx)
		if !ok || p.AuthInfo == nil {
			slog.Warn("TLS-Bypass attempt blocked: transport security credentials missing")
			return nil, status.Error(codes.Unauthenticated, "transport security credentials missing")
		}

		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
			// ЖЕСТКИЙ Fail-Fast отказ: если клиент вызвал Sync без сертификата, рвем сессию!
			slog.Warn("TLS-Bypass attack blocked: client metadata present but no mTLS certificate provided")
			return nil, status.Error(codes.Unauthenticated, "mutual TLS authentication is strictly required for this resource")
		}

		// Извлекаем листовой сертификат устройства, который проскочил проверку 'VerifyClientCertIfGiven'
		clientCert := tlsInfo.State.PeerCertificates[0]

		// 3. РУЧНАЯ КРИПТОГРАФИЧЕСКАЯ ВЕРИФИКАЦИЯ ЦЕПОЧКИ (Второй рубеж обороны)
		// Так как стандартная библиотека пропустила сертификат в режиме IfGiven,
		// мы обязаны принудительно проверить подпись против нашего Device CA здесь.
		opts := x509.VerifyOptions{
			Roots:       in.deviceCAPool,
			CurrentTime: time.Now().UTC(),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		if _, err := clientCert.Verify(opts); err != nil {
			slog.ErrorContext(context.Background(), "mTLS cryptographic validation failed: client used untrusted CA or expired passport")
			// Маскируем сырую ошибку x509 для защиты от Information Disclosure
			return nil, status.Error(codes.Unauthenticated, "client certificate verification failed")
		}

		// 4. ИЗВЛЕЧЕНИЕ КОНТЕКСТА УСТРОЙСТВА (SAN URI)
		var deviceID string
		for _, uri := range clientCert.URIs {
			uriStr := uri.String()
			if strings.HasPrefix(uriStr, ExpectedURIPrefix) {
				deviceID = strings.TrimPrefix(uriStr, ExpectedURIPrefix)
				break
			}
		}

		if strings.TrimSpace(deviceID) == "" {
			slog.Warn("mTLS anomaly: certificate is validly signed by Device CA, but lacks canonical GophKeeper SAN URI")
			return nil, status.Error(codes.Unauthenticated, "invalid client identity: missing or malformed container SAN URI")
		}

		slog.Debug("mTLS session successfully established and authorized on shared port",
			slog.String("device_id", deviceID),
		)

		// 5. Прокидываем проверенный DeviceID в контекст
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
