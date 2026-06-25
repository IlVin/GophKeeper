// Package app координирует рантайм-контейнер ресурсов серверной части приложения,
// управляя процессами инициализации, сетевого вещания и безопасной остановки.
package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"gophkeeper/internal/server/auth"
	"gophkeeper/internal/server/config"
	"gophkeeper/internal/server/pki"
	"gophkeeper/internal/server/providers/postgres"
	servergrpc "gophkeeper/internal/server/transport/grpc"

	"github.com/pires/go-proxyproto"
	"github.com/spf13/viper"
	"golang.org/x/crypto/acme/autocert"
)

// Bootstrap координирует пошаговый запуск и инициализацию всех ресурсов облачного сервера.
//
// Функция загружает конфигурацию, поднимает транзакционный слой PostgreSQL,
// накатывает миграции Goose, разворачивает PKI-инфраструктуру, настраивает гибридный
// TLS/mTLS 1.3 канал и собирает готовый контейнер App (Инварианты №4, №9, №12, №13).
func Bootstrap(ctx context.Context, v *viper.Viper) (context.Context, *App, error) {
	slog.Info("Starting server pre-flight bootstrap and resource allocation pipeline")

	if err := config.ReadConfigFile(v); err != nil {
		return ctx, nil, fmt.Errorf("read server config: %w", err)
	}

	cfg, err := config.LoadFromViper(v)
	if err != nil {
		return ctx, nil, fmt.Errorf("load server config: %w", err)
	}

	// 1. Инициализация и подключение пула СУБД PostgreSQL
	pool, err := postgres.Connect(ctx, cfg.Storage)
	if err != nil {
		return ctx, nil, fmt.Errorf("initialize database layer: %w", err)
	}

	// Флаг для каскадной экстренной очистки ресурсов в случае сбоев на промежуточных шагах
	bootstrapSuccess := false
	var acmeHTTPListener net.Listener
	var rawGrpcListener net.Listener

	defer func() {
		if !bootstrapSuccess {
			slog.ErrorContext(context.Background(), "Bootstrap pipeline collapsed, triggering emergency resource rollback cascade")
			if acmeHTTPListener != nil {
				_ = acmeHTTPListener.Close()
			}
			if rawGrpcListener != nil {
				_ = rawGrpcListener.Close()
			}
			if pool != nil {
				pool.Close()
			}
		}
	}()

	slog.Debug("Applying required database evolutionary schema migrations via Goose")
	if err := postgres.Migrate(pool); err != nil {
		return ctx, nil, fmt.Errorf("apply server database migrations: %w", err)
	}

	var tlsConfig *tls.Config
	var deviceCert *x509.Certificate

	// 2. Инициализация PKI и TLS/mTLS слоев защиты
	if strings.TrimSpace(cfg.Server.LetsEncryptDomain) != "" {
		slog.Info("Enforcing Automated Certificate Management Environment (ACME) via Let's Encrypt",
			slog.String("domain", cfg.Server.LetsEncryptDomain),
		)

		certManager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Server.LetsEncryptDomain),
			Cache:      postgres.NewPostgresCache(pool),
		}

		// ClientAuth переведен в VerifyClientCertIfGiven для гибридной работы TLS/mTLS на одном порту
		tlsConfig = &tls.Config{
			GetCertificate: certManager.GetCertificate,
			MinVersion:     tls.VersionTLS13,
			ClientAuth:     tls.VerifyClientCertIfGiven,
		}

		acmeHTTPListener, err = net.Listen("tcp", cfg.Server.BindHTTP)
		if err != nil {
			slog.Warn("Failed to listen on HTTP socket for ACME challenge verifications",
				slog.String("bind", cfg.Server.BindHTTP),
				slog.Any("error", err),
			)
		} else {
			go func() {
				slog.Debug("Starting automated HTTP ACME challenge listener daemon")
				if serveErr := http.Serve(acmeHTTPListener, certManager.HTTPHandler(nil)); serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
					slog.ErrorContext(context.Background(), "ACME HTTP server daemon collapsed",
						slog.Any("error", serveErr),
					)
				}
			}()
		}
	} else {
		slog.Info("Relying on local CA private keys and self-signed infrastructure for TLS context")

		caCert, caPrivKey, err := pki.LoadServerCA(cfg)
		if err != nil {
			return ctx, nil, fmt.Errorf("load server ca: %w", err)
		}

		host := cfg.Server.ServerName

		serverCert, err := pki.GenerateDynamicServerCertificate(caCert, caPrivKey, host)
		if err != nil {
			return ctx, nil, fmt.Errorf("generate dynamic server cert: %w", err)
		}

		dCert, _, err := pki.LoadDeviceCA(cfg)
		if err != nil {
			return ctx, nil, fmt.Errorf("load device ca trust root: %w", err)
		}
		deviceCert = dCert

		clientCAPool := x509.NewCertPool()
		clientCAPool.AddCert(deviceCert)

		// Настроен режим VerifyClientCertIfGiven для разделения анонимного и mTLS трафика
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*serverCert},
			ClientCAs:    clientCAPool,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			MinVersion:   tls.VersionTLS13,
		}
	}

	// 3. Открытие и конфигурация слушателя входящего gRPC вещания
	slog.Debug("Opening main gRPC TCP listening network socket descriptor",
		slog.String("bind", cfg.Server.BindGRPC),
	)
	rawGrpcListener, err = net.Listen("tcp", cfg.Server.BindGRPC)
	if err != nil {
		return ctx, nil, fmt.Errorf("listen grpc socket %s: %w", cfg.Server.BindGRPC, err)
	}

	var grpcListener net.Listener = rawGrpcListener
	if cfg.Server.UseProxyProtocol {
		slog.Debug("Enabling PROXY protocol v1/v2 header parser wrap on gRPC socket")
		grpcListener = &proxyproto.Listener{
			Listener:          rawGrpcListener,
			ReadHeaderTimeout: 10 * time.Second,
		}
	}

	// 4. Сборка интерцепторов безопасности и окончательного контейнера App
	slog.Debug("Injecting active context auth interceptor and assembling gRPC server instance")
	interceptor, err := auth.NewAuthInterceptor(pool)
	if err != nil {
		return ctx, nil, fmt.Errorf("initialize auth interceptor: %w", err)
	}
	grpcServer := servergrpc.NewGRPCServer(cfg, tlsConfig, pool, interceptor)

	application := NewApp(cfg, grpcListener, grpcServer, pool, acmeHTTPListener)

	// Активируем флаг успеха, отключая экстренный откат ресурсов в defer
	bootstrapSuccess = true

	slog.Info("Server environment bootstrap completed successfully. Composition Root initialized.")
	ctx = WithApp(ctx, application)
	return ctx, application, nil
}
