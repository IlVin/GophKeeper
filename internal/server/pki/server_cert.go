package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// GenerateDynamicServerCertificate создает TLS-сертификат для gRPC-сервера на лету,
// подписывая его предоставленным Server CA.
func GenerateDynamicServerCertificate(caCert *x509.Certificate, caPrivateKey *ecdsa.PrivateKey, host string) (*tls.Certificate, error) {
	if caCert == nil || caPrivateKey == nil {
		return nil, fmt.Errorf("ca certificates and private keys cannot be nil")
	}
	if host == "" {
		return nil, fmt.Errorf("target server host cannot be empty")
	}

	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GophKeeper Storage Network"},
			CommonName:   host,
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, // Строго ServerAuth
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	template.DNSNames = append(template.DNSNames, "localhost")

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverPrivKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{serverCertDER, caCert.Raw},
		PrivateKey:  serverPrivKey,
	}, nil
}
