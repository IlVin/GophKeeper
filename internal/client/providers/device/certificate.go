package device

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/url"
)

// GenerateContainerCSR генерирует новую пару ключей ECDSA P-256 для mTLS и создает PKCS#10 CSR blob.
func GenerateContainerCSR(deviceID string) (rawPrivateKey []byte, csrBytes []byte, err error) {
	// 1. Генерируем ключ на эллиптической кривой NIST P-256 (вместо медленного RSA)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ecdsa p-256 key: %w", err)
	}

	// 2. Маршалируем приватный ключ в универсальный стандарт PKCS#8
	rawPriv, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key to pkcs8: %w", err)
	}

	subj := pkix.Name{
		Organization: []string{"GophKeeper Container Storage Network"},
		CommonName:   fmt.Sprintf("GophKeeper Client Container %s", deviceID),
	}

	// 3. Переводим алгоритм подписи запроса на ECDSA-SHA256
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	// Инвариант mTLS: вшиваем в SAN URI уникальный URN-идентификатор нашего SQLite контейнера
	if uri, err := url.Parse(fmt.Sprintf("urn:gophkeeper:file:%s", deviceID)); err == nil {
		template.URIs = []*url.URL{uri}
	}

	// 4. Подписываем CSR сгенерированным ECDSA ключом
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	return rawPriv, csrDER, nil
}
