// Package pki предоставляет инструменты управления инфраструктурой открытых ключей,
// динамической генерации TLS-сертификатов и выпуска mTLS-паспортов устройств.
package pki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"time"
)

// GenerateDynamicServerCertificate создает TLS-сертификат для gRPC-сервера на лету,
// подписывая его предоставленным корневым сертификатом Server CA.
//
// Функция автоматически пробрасывает SAN IP/DNS параметры для localhost, 127.0.0.1
// и целевого хоста. В случае промежуточных сбоев гарантирует выжигание ключей из RAM.
func GenerateDynamicServerCertificate(caCert *x509.Certificate, caPrivateKey *ecdsa.PrivateKey, host string) (*tls.Certificate, error) {
	if caCert == nil || caPrivateKey == nil {
		return nil, errors.New("ca certificates and private keys cannot be nil")
	}
	if host == "" {
		return nil, errors.New("target server host cannot be empty")
	}

	slog.Debug("Generating new ephemeral ecdsa p-256 key pair for server TLS context")
	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.ErrorContext(context.Background(), "Failed to generate server P-256 cryptographic key pair",
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to generate server private key: %w", err)
	}

	// ГАРАНТИЯ ИБ (RAM Hygiene): Если последующие шаги упадут,
	// принудительно выжигаем секретный множитель D закрытого ключа из памяти кучи
	cleanUpNeeded := true
	defer func() {
		if cleanUpNeeded && serverPrivKey != nil && serverPrivKey.D != nil {
			serverPrivKey.D.SetInt64(0)
			serverPrivKey.D = big.NewInt(0)
			slog.Debug("Emergency erasure of ephemeral server private key material from RAM completed")
		}
	}()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		slog.ErrorContext(context.Background(), "CSPRNG entropy extraction failed for server cert serial number generation",
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GophKeeper Storage Network"},
			CommonName:   host,
		},
		NotBefore:             time.Now().Add(-5 * time.Minute), // Санитарный зазор рассинхронизации часов
		NotAfter:              time.Now().AddDate(1, 0, 0),      // Срок действия ровно 1 год
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, // Строго ServerAuth
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Настраиваем Subject Alternative Names (SAN)
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	// Принудительный анкоринг локальных диагностических интерфейсов в SAN
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	template.DNSNames = append(template.DNSNames, "localhost")

	slog.Debug("Signing dynamic server TLS certificate via Server CA root key",
		slog.String("host", host),
	)
	serverCertDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverPrivKey.PublicKey, caPrivateKey)
	if err != nil {
		slog.ErrorContext(context.Background(), "PKI factory failed to sign dynamic server x509 certificate",
			slog.Any("error", err),
		)
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Успешный конвейер: снимаем флаг экстренной очистки, отдаем TLS-пакет в рантайм
	cleanUpNeeded = false

	slog.Info("Successfully generated dynamic server TLS certificate context",
		slog.String("host", host),
	)
	return &tls.Certificate{
		Certificate: [][]byte{serverCertDER, caCert.Raw},
		PrivateKey:  serverPrivKey,
	}, nil
}
