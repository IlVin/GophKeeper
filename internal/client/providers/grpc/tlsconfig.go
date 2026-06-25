// Package grpc предоставляет инструменты настройки сетевого транспорта,
// параметров криптографической защиты каналов и конфигурации TLS-соединений.
package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"

	"gophkeeper/internal/shared/certs"
)

var (
	// ErrEmptyCertificate возвращается, если в конфигуратор mTLS передан пустой паспорт устройства.
	ErrEmptyCertificate = errors.New("client mTLS certificate cannot be empty")
)

// ConfigForBootstrap генерирует конфигурацию TLS для первичного недоверенного
// подключения к серверу (фаза регистрации/получения соли).
//
// Намертво ограничивает минимальную версию протокола до TLS 1.3 и привязывает
// клиента к доверенному встроенному Server CA пулу для защиты от MitM-атак.
func ConfigForBootstrap() (*tls.Config, error) {
	slog.Debug("Assembling secure TLS 1.3 configuration for bootstrap connection phase")

	pool, err := certs.LoadServerCAPool()
	if err != nil {
		slog.ErrorContext(context.Background(), "Failed to load embedded server CA pool for bootstrap TLS",
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("load server CA pool: %w", err)
	}

	return &tls.Config{
		RootCAs:      pool,
		Certificates: nil,
		MinVersion:   tls.VersionTLS13, // Принудительный ИБ-инвариант TLS 1.3
	}, nil
}

// ConfigForMTLS генерирует конфигурацию для двусторонней mTLS 1.3 аутентификации
// локального контейнера на серверах GophKeeper (фаза синхронизации данных).
//
// Если caPool равен nil, функция автоматически подгрузит встроенный Server CA.
func ConfigForMTLS(cert tls.Certificate, caPool *x509.CertPool) (*tls.Config, error) {
	slog.Debug("Assembling secure mutual TLS 1.3 configuration for operational sync phase")

	// Проверяем валидность переданного mTLS паспорта устройства
	if len(cert.Certificate) == 0 {
		slog.Error("DACL/mTLS configuration rejected: provided client certificate is empty")
		return nil, ErrEmptyCertificate
	}

	if caPool == nil {
		slog.Debug("Custom CA pool is nil, executing lazy load of embedded server CA pool")
		var err error
		caPool, err = certs.LoadServerCAPool()
		if err != nil {
			slog.ErrorContext(context.Background(), "Failed to lazy load embedded server CA pool for mTLS",
				slog.Any("error", err),
			)
			return nil, fmt.Errorf("load server CA pool: %w", err)
		}
	}

	return &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // Исключаем использование уязвимого TLS 1.2
	}, nil
}
