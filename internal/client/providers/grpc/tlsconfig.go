package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"gophkeeper/internal/shared/certs"
)

func ConfigForBootstrap() (*tls.Config, error) {
	pool, err := certs.LoadServerCAPool()
	if err != nil {
		return nil, fmt.Errorf("load server CA pool: %w", err)
	}

	return &tls.Config{
		RootCAs:      pool,
		Certificates: nil,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func ConfigForMTLS(cert tls.Certificate, caPool *x509.CertPool) (*tls.Config, error) {
	if caPool == nil {
		var err error
		caPool, err = certs.LoadServerCAPool()
		if err != nil {
			return nil, fmt.Errorf("load server CA pool: %w", err)
		}
	}

	return &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func ConfigForTest() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
	}
}
