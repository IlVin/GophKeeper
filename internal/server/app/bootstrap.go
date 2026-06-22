package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"gophkeeper/internal/server/auth"
	"gophkeeper/internal/server/config"
	"gophkeeper/internal/server/pki"
	"gophkeeper/internal/server/providers/postgres"
	servergrpc "gophkeeper/internal/server/transport/grpc"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/spf13/viper"
	"golang.org/x/crypto/acme/autocert"
)

// Bootstrap координирует запуск сервера: загружает конфигурацию, настраивает строгий mTLS и поднимает gRPC.
func Bootstrap(ctx context.Context, v *viper.Viper) (context.Context, *App, error) {
	if err := config.ReadConfigFile(v); err != nil {
		return ctx, nil, fmt.Errorf("read server config: %w", err)
	}

	cfg, err := config.LoadFromViper(v)
	if err != nil {
		return ctx, nil, fmt.Errorf("load server config: %w", err)
	}

	pool, err := postgres.Connect(ctx, cfg.Storage)
	if err != nil {
		return ctx, nil, fmt.Errorf("initialize database layer: %w", err)
	}

	if err := postgres.Migrate(pool); err != nil {
		pool.Close()
		return ctx, nil, fmt.Errorf("apply server database migrations: %w", err)
	}

	var tlsConfig *tls.Config
	var acmeHTTPListener net.Listener
	var deviceCert *x509.Certificate // ДОБАВЛЕНО: Объявляем переменную на уровне функции для корректного Scope

	if strings.TrimSpace(cfg.Server.LetsEncryptDomain) != "" {
		certManager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Server.LetsEncryptDomain),
			Cache:      postgres.NewPostgresCache(pool),
		}

		tlsConfig = &tls.Config{
			GetCertificate: certManager.GetCertificate,
			MinVersion:     tls.VersionTLS13,
			ClientAuth:     tls.VerifyClientCertIfGiven,
		}

		var acmeErr error
		acmeHTTPListener, acmeErr = net.Listen("tcp", cfg.Server.BindHTTP)
		if acmeErr != nil {
			fmt.Printf("Warning: failed to listen on HTTP socket %s for ACME challenge: %v\n", cfg.Server.BindHTTP, acmeErr)
		} else {
			go func() {
				_ = http.Serve(acmeHTTPListener, certManager.HTTPHandler(nil))
			}()
		}
	} else {
		// Загрузка Server CA с передачей объекта внешней конфигурации
		caCert, caPrivKey, err := pki.LoadServerCA(cfg)
		if err != nil {
			pool.Close()
			return ctx, nil, fmt.Errorf("load server ca: %w", err)
		}

		host, _, err := net.SplitHostPort(cfg.Server.BindGRPC)
		if err != nil || host == "" {
			host = "localhost"
		}

		serverCert, err := pki.GenerateDynamicServerCertificate(caCert, caPrivKey, host)
		if err != nil {
			pool.Close()
			return ctx, nil, fmt.Errorf("generate dynamic server cert: %w", err)
		}

		// ИСПРАВЛЕНО: Присваиваем значение внешней переменной без оператора := (чтобы не перекрывать Scope)
		var dCert *x509.Certificate
		dCert, _, err = pki.LoadDeviceCA(cfg)
		if err != nil {
			pool.Close()
			return ctx, nil, fmt.Errorf("load device ca trust root: %w", err)
		}
		deviceCert = dCert

		clientCAPool := x509.NewCertPool()
		clientCAPool.AddCert(deviceCert)

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*serverCert},
			ClientCAs:    clientCAPool,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			MinVersion:   tls.VersionTLS13,
		}
	}

	rawGrpcListener, err := net.Listen("tcp", cfg.Server.BindGRPC)
	if err != nil {
		if acmeHTTPListener != nil {
			_ = acmeHTTPListener.Close()
		}
		pool.Close()
		return ctx, nil, fmt.Errorf("listen grpc socket %s: %w", cfg.Server.BindGRPC, err)
	}

	var grpcListener net.Listener = rawGrpcListener
	if cfg.Server.UseProxyProtocol {
		grpcListener = &proxyproto.Listener{
			Listener:          rawGrpcListener,
			ReadHeaderTimeout: 10 * time.Second,
		}
	}

	// Инициализируем перехватчик. Если мы в режиме Let's Encrypt, deviceCert будет nil,
	// и интерцептор создаст пустой пул (для MVP это штатное поведение, если mTLS не настроен).
	interceptor := auth.NewAuthInterceptor(pool)
	grpcServer := servergrpc.NewGRPCServer(cfg, tlsConfig, pool, interceptor)

	application := NewApp(cfg, grpcListener, grpcServer, acmeHTTPListener)
	application.Pool = pool

	ctx = WithApp(ctx, application)
	return ctx, application, nil
}
