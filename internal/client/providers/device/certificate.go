package device

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var (
	ErrNoPrivateKey  = errors.New("no private key found in PEM")
	ErrNoCertificate = errors.New("no certificate found in PEM")
)

func LoadDeviceCertificate(certPEM, keyPEM []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse X509 key pair: %w", err)
	}

	if err := validateClientCertificate(&cert); err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

func validateClientCertificate(cert *tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return ErrNoCertificate
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	clientAuthFound := false
	for _, usage := range x509Cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuthFound = true
			break
		}
	}
	if !clientAuthFound {
		return fmt.Errorf("certificate missing clientAuth ExtendedKeyUsage")
	}

	return nil
}

func EncapsulateDeviceCertificate(cert tls.Certificate) (certPEM, keyPEM []byte, err error) {
	for _, certDER := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})...)
	}

	if cert.PrivateKey == nil {
		return nil, nil, ErrNoPrivateKey
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM, nil
}
