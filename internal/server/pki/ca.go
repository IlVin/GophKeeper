package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"gophkeeper/internal/server/config"
	"gophkeeper/internal/shared/certs"
)

// LoadServerCA парсит публичный сертификат из памяти бинарника,
// а закрытый ключ загружает с диска (Инвариант v4.1).
func LoadServerCA(cfg config.Config) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if cfg.PKI.ServerCAKeyPath == "" {
		return nil, nil, fmt.Errorf("server ca private key path is not configured")
	}

	// 1. Извлекаем публичный сертификат напрямую из go:embed ассетов
	block, _ := pem.Decode(certs.ServerCAPEM())
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode embedded server ca certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse embedded server ca certificate: %w", err)
	}

	// 2. Читаем закрытый ключ сервера с диска
	ecdsaKey, err := loadPrivateKeyFromFile(cfg.PKI.ServerCAKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("server ca key load from %q: %w", cfg.PKI.ServerCAKeyPath, err)
	}

	return caCert, ecdsaKey, nil
}

// LoadDeviceCA парсит публичный сертификат из памяти бинарника,
// а закрытый ключ загружает с диска (Инвариант v4.1).
func LoadDeviceCA(cfg config.Config) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if cfg.PKI.DeviceCAKeyPath == "" {
		return nil, nil, fmt.Errorf("device ca private key path is not configured")
	}

	// 1. Извлекаем публичный сертификат напрямую из go:embed ассетов
	block, _ := pem.Decode(certs.DeviceCAPEM())
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode embedded device ca certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse embedded device ca certificate: %w", err)
	}

	// 2. Читаем закрытый ключ устройства с диска
	ecdsaKey, err := loadPrivateKeyFromFile(cfg.PKI.DeviceCAKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("device ca key load from %q: %w", cfg.PKI.DeviceCAKeyPath, err)
	}

	return caCert, ecdsaKey, nil
}

func loadPrivateKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil || (keyBlock.Type != "EC PRIVATE KEY" && keyBlock.Type != "PRIVATE KEY") {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	var privKey any
	var errParse error
	privKey, errParse = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if errParse != nil {
		privKey, errParse = x509.ParseECPrivateKey(keyBlock.Bytes)
		if errParse != nil {
			return nil, fmt.Errorf("parse key bytes: %w", errParse)
		}
	}

	ecdsaKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an ECDSA private key")
	}

	return ecdsaKey, nil
}
