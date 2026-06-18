package certs

import (
	"crypto/x509"
	"errors"
	"fmt"
)

var (
	ErrEmptyCA       = errors.New("CA certificate is empty")
	ErrInvalidCACert = errors.New("invalid CA certificate")
)

func LoadServerCAPool() (*x509.CertPool, error) {
	pemBytes := ServerCAPEM()
	if len(pemBytes) == 0 {
		return nil, ErrEmptyCA
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%w: failed to parse server CA certificate", ErrInvalidCACert)
	}

	return pool, nil
}

func LoadDeviceCAPool() (*x509.CertPool, error) {
	pemBytes := DeviceCAPEM()
	if len(pemBytes) == 0 {
		return nil, ErrEmptyCA
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%w: failed to parse device CA certificate", ErrInvalidCACert)
	}

	return pool, nil
}
