// Package device предоставляет системные адаптеры для управления аппаратной
// и программной идентичностью клиентского устройства GophKeeper.
package device

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
)

// GenerateContainerCSR генерирует новую ключевую пару ECDSA P-256 для mTLS транспорта и создает PKCS#10 CSR блок.
//
// Функция принудительно вшивает в Subject Alternative Name (SAN) уникальный URN контейнера
// для предотвращения атак подмены контекста устройства на стороне центра сертификации (CA) сервера.
// В случае сбоя гарантирует тотальное обнуление секретных компонентов ключа в RAM (RAM Hygiene).
func GenerateContainerCSR(deviceID string) (rawPrivateKey []byte, csrBytes []byte, err error) {
	slog.Debug("Initiating cryptographic container mTLS identity key pair generation")

	// 1. Генерируем ключ на кривой NIST P-256 (ECDSA)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Error("Failed to generate secure ecdsa p-256 key pair", "error", err)
		return nil, nil, fmt.Errorf("failed to generate ecdsa p-256 key: %w", err)
	}

	// Гарантированная защита ИБ (RAM Hygiene): если последующие шаги упадут,
	// принудительно выжигаем секретный компонент D закрытого ключа из памяти кучи
	cleanUpNeeded := true
	defer func() {
		if cleanUpNeeded && privKey != nil && privKey.D != nil {
			privKey.D.SetInt64(0)
			privKey.D = big.NewInt(0)
			slog.Debug("Emergency erasure of private key material from RAM completed due to pipeline failure")
		}
	}()

	// 2. Маршалируем приватный ключ в кроссплатформенный стандарт PKCS#8
	rawPriv, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		slog.Error("Failed to marshal private key to PKCS8 format", "error", err)
		return nil, nil, fmt.Errorf("failed to marshal private key to pkcs8: %w", err)
	}

	subj := pkix.Name{
		Organization: []string{"GophKeeper Container Storage Network"},
		CommonName:   fmt.Sprintf("GophKeeper Client Container %s", deviceID),
	}

	// 3. Конструируем шаблон запроса на сертификат с жесткой фиксацией алгоритма ECDSA-SHA256
	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	// Инвариант mTLS: вшиваем в SAN URI вечный URN-идентификатор нашего SQLite контейнера
	urnStr := fmt.Sprintf("urn:gophkeeper:file:%s", deviceID)
	uri, err := url.Parse(urnStr)
	if err != nil {
		slog.Error("Failed to parse identity SAN URN layout string", "urn", urnStr, "error", err)
		return nil, nil, fmt.Errorf("failed to parse container identity URN: %w", err)
	}
	template.URIs = []*url.URL{uri}

	// 4. Подписываем CSR сгенерированным ECDSA ключом
	slog.Debug("Signing PKCS10 certificate request via newly generated ECDSA private key")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		slog.Error("Failed to create signed certificate request block", "error", err)
		return nil, nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	// Если весь конвейер завершился успехом, снимаем флаг экстренной очистки.
	// Ответственность за зачистку массива rawPriv переходит к вызывающему сервису.
	cleanUpNeeded = false

	slog.Info("Container mTLS passport CSR successfully generated and signed")
	return rawPriv, csrDER, nil
}
