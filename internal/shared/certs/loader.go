// Package certs инкапсулирует встроенные криптографические сертификаты
// удостоверяющих центров (CA) и методы загрузки пулов доверия.
package certs

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

var (
	// ErrEmptyCA возвращается, если встроенный PEM-массив байт CA пуст.
	ErrEmptyCA = errors.New("CA certificate is empty")

	// ErrInvalidCACert возвращается, если парсер x509 не смог распознать PEM-структуру сертификата.
	ErrInvalidCACert = errors.New("invalid CA certificate")
)

var (
	serverPoolInstance *x509.CertPool
	serverPoolError    error
	serverOnce         sync.Once

	devicePoolInstance *x509.CertPool
	devicePoolError    error
	deviceOnce         sync.Once
)

// LoadServerCAPool возвращает потокобезопасный иммутабельный пул корневых сертификатов Server CA.
//
// Реализует паттерн ленивого синглтона через sync.Once, предотвращая повторные дорогостоящие
// аллокации и парсинг ASN.1 структур в конкурентных горутинах CLI-рантайма.
func LoadServerCAPool() (*x509.CertPool, error) {
	serverOnce.Do(func() {
		slog.Debug("Executing atomic lazy initialization of x509 Server CA cert pool")
		pemBytes := ServerCAPEM()
		if len(pemBytes) == 0 {
			serverPoolError = ErrEmptyCA
			return
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			serverPoolError = fmt.Errorf("%w: failed to parse server CA certificate", ErrInvalidCACert)
			return
		}
		serverPoolInstance = pool
		slog.Debug("Server CA cert pool successfully parsed and locked in global RAM context")
	})

	if serverPoolError != nil {
		return nil, serverPoolError
	}
	return serverPoolInstance, nil
}

// LoadDeviceCAPool возвращает потокобезопасный пул корневых сертификатов Device CA.
//
// Используется серверными компонентами для валидации mTLS паспортов входящих клиентов.
func LoadDeviceCAPool() (*x509.CertPool, error) {
	deviceOnce.Do(func() {
		slog.Debug("Executing atomic lazy initialization of x509 Device CA cert pool")
		pemBytes := DeviceCAPEM()
		if len(pemBytes) == 0 {
			devicePoolError = ErrEmptyCA
			return
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			devicePoolError = fmt.Errorf("%w: failed to parse device CA certificate", ErrInvalidCACert)
			return
		}
		devicePoolInstance = pool
		slog.Debug("Device CA cert pool successfully parsed and locked in global RAM context")
	})

	if devicePoolError != nil {
		return nil, devicePoolError
	}
	return devicePoolInstance, nil
}
