// Package pki предоставляет инструменты управления инфраструктурой открытых ключей,
// динамической генерации TLS-сертификатов и выпуска mTLS-паспортов устройств.
package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"gophkeeper/internal/server/config"
	"gophkeeper/internal/shared/certs"
)

// LoadServerCA извлекает публичный сертификат из памяти бинарника,
// а закрытый ключ загружает с диска хоста для обеспечения ИБ-изоляции.
func LoadServerCA(cfg config.Config) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if cfg.PKI.ServerCAKeyPath == "" {
		return nil, nil, errors.New("server ca private key path is not configured")
	}

	slog.Debug("Parsing embedded Server CA public certificate PEM block")
	block, _ := pem.Decode(certs.ServerCAPEM())
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("failed to decode embedded server ca certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse embedded server ca certificate: %w", err)
	}

	slog.Info("Loading Server CA private key material from secure local storage", "path", cfg.PKI.ServerCAKeyPath)
	ecdsaKey, err := loadPrivateKeyFromFile(cfg.PKI.ServerCAKeyPath)
	if err != nil {
		slog.Error("Failed to initialize Server CA root private key descriptor", "path", cfg.PKI.ServerCAKeyPath, "error", err)
		return nil, nil, fmt.Errorf("server ca key load from %q: %w", cfg.PKI.ServerCAKeyPath, err)
	}

	return caCert, ecdsaKey, nil
}

// LoadDeviceCA извлекает публичный сертификат из памяти бинарника,
// а закрытый ключ загружает с диска хоста для обеспечения ИБ-изоляции.
func LoadDeviceCA(cfg config.Config) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if cfg.PKI.DeviceCAKeyPath == "" {
		return nil, nil, errors.New("device ca private key path is not configured")
	}

	slog.Debug("Parsing embedded Device CA public certificate PEM block")
	block, _ := pem.Decode(certs.DeviceCAPEM())
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("failed to decode embedded device ca certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse embedded device ca certificate: %w", err)
	}

	slog.Info("Loading Device CA private key material from secure local storage", "path", cfg.PKI.DeviceCAKeyPath)
	ecdsaKey, err := loadPrivateKeyFromFile(cfg.PKI.DeviceCAKeyPath)
	if err != nil {
		slog.Error("Failed to initialize Device CA root private key descriptor", "path", cfg.PKI.DeviceCAKeyPath, "error", err)
		return nil, nil, fmt.Errorf("device ca key load from %q: %w", cfg.PKI.DeviceCAKeyPath, err)
	}

	return caCert, ecdsaKey, nil
}

// loadPrivateKeyFromFile осуществляет чтение и ASN.1 DER декодирование закрытого ECDSA ключа.
// Гарантирует принудительное выжигание буферов памяти нулями при любых промежуточных сбоях.
func loadPrivateKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	// ГАРАНТИЯ ИБ (RAM Hygiene): Обеспечиваем затирание сырых байтов ключа в куче при выходах с ошибками
	cleanUpNeeded := true
	defer func() {
		if cleanUpNeeded {
			for i := range keyBytes {
				keyBytes[i] = 0
			}
			slog.Debug("Emergency erasure of raw key bytes from heap completed due to parsing failure")
		}
	}()

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || (keyBlock.Type != "EC PRIVATE KEY" && keyBlock.Type != "PRIVATE KEY") {
		return nil, errors.New("failed to decode private key PEM layout")
	}

	// Защищаем внутренний ASN.1 блок деривации внутри PEM-структуры
	defer func() {
		if cleanUpNeeded && keyBlock != nil {
			for i := range keyBlock.Bytes {
				keyBlock.Bytes[i] = 0
			}
		}
	}()

	var privKey any
	var errParse error

	// Пробуем распарсить по каноническому стандарту PKCS#8
	privKey, errParse = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if errParse != nil {
		// Резервный шаг: пробуем распарсить как SEC1 EC Private Key
		privKey, errParse = x509.ParseECPrivateKey(keyBlock.Bytes)
		if errParse != nil {
			return nil, fmt.Errorf("failed to parse key bytes via PKCS8/SEC1: %w", errParse)
		}
	}

	ecdsaKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not an ECDSA private key")
	}

	// Успешный путь: снимаем флаг экстренной очистки.
	// Оригинальный массив keyBytes зануляется для пресечения утечек.
	cleanUpNeeded = false
	for i := range keyBytes {
		keyBytes[i] = 0
	}

	return ecdsaKey, nil
}
