package auth

import (
	"context"
	"crypto/x509"
	"gophkeeper/internal/shared/certs"
	"strings"
	"time"

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

// AuthInterceptor инкапсулирует пул доверенных корневых сертификатов устройств для ручной верификации
type AuthInterceptor struct {
	deviceCAPool *x509.CertPool
	pool         *pgxpool.Pool // Для проверки статуса в БД
}

// NewAuthInterceptor создает экземпляр перехватчика с привязкой к Device CA Trust Root
func NewAuthInterceptor(dbPool *pgxpool.Pool) *AuthInterceptor {
	// Вызываем ваш готовый загрузчик встроенного пула Device CA
	devicePool, err := certs.LoadDeviceCAPool()
	if err != nil {
		// Если эмбед пустой, сервер упадет на старте (Fail-Fast)
		panic("critical: failed to load embedded device CA trust root: " + err.Error())
	}

	return &AuthInterceptor{
		deviceCAPool: devicePool,
		pool:         dbPool,
	}
}

// UnaryAuthInterceptor проверяет mTLS сертификаты устройств и защищает от TLS-bypass атак
func (in *AuthInterceptor) UnaryAuthInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		// 1. Разрешаем свободный доступ к challenge-методам регистрации и привязки
		if isPublicEndpoint(info.FullMethod) {
			return handler(ctx, req)
		}

		// 2. Извлекаем TLS-информацию о подключенном пире
		p, ok := peer.FromContext(ctx)
		if !ok || p.AuthInfo == nil {
			return nil, status.Error(codes.Unauthenticated, "missing transport security credentials")
		}

		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
			return nil, status.Error(codes.Unauthenticated, "mTLS client certificate is required for sync channels")
		}

		// Извлекаем первый (листовой) сертификат контейнера
		clientCert := tlsInfo.State.PeerCertificates[0]

		// 3. КРИТИЧЕСКИЙ БАРЬЕР: Вручную верифицируем цепочку подписей сертификата против DeviceCA (Инвариант mTLS)
		// Так как сервер работает в режиме VerifyClientCertIfGiven, мы обязаны отсечь невалидные подписи здесь
		opts := x509.VerifyOptions{
			Roots:       in.deviceCAPool,
			CurrentTime: time.Now().UTC(),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		if _, err := clientCert.Verify(opts); err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "client certificate verification failed (untrusted chain or expired): %v", err)
		}

		// 4. Извлекаем и сканируем Subject Alternative Names (SAN) в поисках URI схемы v4.0
		var deviceID string
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

		// 5. Помещаем верифицированный DeviceID в контекст запроса для бизнес-логики
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
