package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

// IssueDeviceCertificate принимает сырые байты CSR (DER/PKCS#10), валидирует его,
// генерирует уникальный серийный номер и подписывает сертификат с помощью Device Identity CA
// строго на 30 дней с пробросом SAN URI контейнера (Инвариант mTLS).
func IssueDeviceCertificate(
	csrDER []byte,
	deviceID string,
	deviceCACert *x509.Certificate,
	deviceCAKey *ecdsa.PrivateKey,
) (rawCertDER []byte, serialNum *big.Int, err error) {
	if len(csrDER) == 0 || deviceID == "" || deviceCACert == nil || deviceCAKey == nil {
		return nil, nil, fmt.Errorf("invalid inputs for device certificate issuance")
	}

	// 1. Десериализуем и парсим входящий запрос CSR
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse client csr: %w", err)
	}

	// Валидируем подпись самого запроса CSR (защита от мусорных/поддельных CSR данных)
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("client csr signature validation failed: %w", err)
	}

	// 2. Генерируем криптографически случайный уникальный Serial Number (до 128 бит)
	// Этот номер будет зафиксирован в PostgreSQL для защиты от replay (mTLS инвариант)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random serial number: %w", err)
	}

	// 3. Конструируем канонический URI контейнера
	containerURI, err := url.Parse(fmt.Sprintf("urn:gophkeeper:file:%s", deviceID))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse target device san uri: %w", err)
	}

	// 4. Формируем шаблон x509 сертификата на основе жестких требований спецификации v4.1
	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GophKeeper Secure Storage Network"},
			CommonName:   fmt.Sprintf("GophKeeper Container %s", deviceID),
		},

		// Срок действия сертификата устройства строго 30 дней по спецификации
		NotBefore: now.Add(-5 * time.Minute), // Санитарный зазор на рассинхронизацию часов
		NotAfter:  now.AddDate(0, 0, 30),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // Строго ClientAuth для mTLS (Инвариант)
		BasicConstraintsValid: true,
		IsCA:                  false,

		// Жестко привязываем SAN URI идентификатор контейнера к телу сертификата
		URIs: []*url.URL{containerURI},
	}

	// 5. Выпускаем и подписываем сертификат ключом нашего закрытого Device Identity CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, deviceCACert, csr.PublicKey, deviceCAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign and create device certificate: %w", err)
	}

	return certDER, serialNumber, nil
}
