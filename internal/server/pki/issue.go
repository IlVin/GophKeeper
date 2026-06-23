// Package pki предоставляет инструменты управления инфраструктурой открытых ключей,
// динамической генерации TLS-сертификатов и выпуска mTLS-паспортов устройств.
package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// IssueDeviceCertificate принимает сырые байты CSR (DER/PKCS#10), валидирует его подпись,
// генерирует уникальный серийный номер и подписывает mTLS сертификат строго на 30 дней.
//
// Функция принудительно вшивает ExtendedKeyUsage=clientAuth и SAN URI контейнера (Инвариант mTLS).
// Защищена от атак Identity Spoofing путем жесткой перекрестной сверки UUID в CSR и хендлере.
func IssueDeviceCertificate(
	csrDER []byte,
	deviceID string,
	deviceCACert *x509.Certificate,
	deviceCAKey *ecdsa.PrivateKey,
) (rawCertDER []byte, serialNum *big.Int, err error) {
	if len(csrDER) == 0 || strings.TrimSpace(deviceID) == "" || deviceCACert == nil || deviceCAKey == nil {
		return nil, nil, errors.New("invalid inputs for device certificate issuance")
	}

	// 1. Десериализуем и парсим входящий запрос CSR
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		slog.Warn("Failed to parse incoming client ASN.1 DER CSR structure", "error", err)
		return nil, nil, fmt.Errorf("failed to parse client csr: %w", err)
	}

	// Валидируем подпись самого запроса CSR (защита от мусорных/поддельных данных)
	if err = csr.CheckSignature(); err != nil {
		slog.Warn("Client CSR public key cryptographic signature validation failed", "error", err)
		return nil, nil, fmt.Errorf("client csr signature validation failed: %w", err)
	}

	// Защитный ИБ-барьер против атак Identity Spoofing.
	// Если клиент передал URI в CSR, проверяем его жесткое совпадение с доменным контекстом
	if len(csr.URIs) > 0 {
		var csrDeviceID string
		const prefix = "urn:gophkeeper:file:"

		for _, u := range csr.URIs {
			uStr := u.String()
			if strings.HasPrefix(uStr, prefix) {
				csrDeviceID = strings.TrimPrefix(uStr, prefix)
				break
			}
		}

		if csrDeviceID != "" && csrDeviceID != deviceID {
			slog.Error("Critical identity mismatch detected between CSR payload and registration arguments",
				"argument_device_id", deviceID, "csr_device_id", csrDeviceID)
			return nil, nil, errors.New("security violation: device identity mismatch in CSR content")
		}
	}

	// 2. Генерируем криптографически случайный уникальный Serial Number (до 128 бит)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		slog.Error("CSPRNG entropy extraction failed for certificate serial number generation", "error", err)
		return nil, nil, fmt.Errorf("failed to generate random serial number: %w", err)
	}

	// 3. Конструируем канонический URI контейнера
	containerURILayout := fmt.Sprintf("urn:gophkeeper:file:%s", deviceID)
	containerURI, err := url.Parse(containerURILayout)
	if err != nil {
		slog.Error("Failed to parse target device SAN URI components layout", "uri", containerURILayout, "error", err)
		return nil, nil, fmt.Errorf("failed to parse target device san uri: %w", err)
	}

	// 4. Формируем шаблон x509 сертификата на основе жестких требований спецификации
	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GophKeeper Secure Storage Network"},
			CommonName:   fmt.Sprintf("GophKeeper Container %s", deviceID),
		},

		// Срок действия сертификата устройства строго 30 дней
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
	slog.Debug("Signing and sealing new x509 mTLS device passport via Device CA root key", "device_id", deviceID)
	certDER, err := x509.CreateCertificate(rand.Reader, &template, deviceCACert, csr.PublicKey, deviceCAKey)
	if err != nil {
		slog.Error("PKI factory failed to execute x509.CreateCertificate signing operation", "error", err)
		return nil, nil, fmt.Errorf("failed to sign and create device certificate: %w", err)
	}

	slog.Info("Successfully issued new mTLS device passport",
		"device_id", deviceID,
		"serial_number", serialNumber.String(),
	)
	return certDER, serialNumber, nil
}
