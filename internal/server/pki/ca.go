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

// LoadServerCA десериализует публичный сертификат (из shared)
// и закрытый ключ CA сервера (из указанного в конфигурации файла).
func LoadServerCA(cfg config.Config) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certBytes := certs.ServerCAPEM()
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode embedded server ca certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse embedded server ca certificate: %w", err)
	}

	if cfg.PKI.ServerCAKeyPath == "" {
		return nil, nil, fmt.Errorf("server ca private key path is not configured")
	}

	ecdsaKey, err := loadPrivateKeyFromFile(cfg.PKI.ServerCAKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("server ca key load: %w", err)
	}

	return caCert, ecdsaKey, nil
}

// LoadDeviceCA полностью загружает и публичный сертификат, и закрытый ключ Device Identity CA из внешних файлов.
func LoadDeviceCA(cfg config.Config) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if cfg.PKI.DeviceCACertPath == "" {
		return nil, nil, fmt.Errorf("device ca certificate path is not configured")
	}
	if cfg.PKI.DeviceCAKeyPath == "" {
		return nil, nil, fmt.Errorf("device ca private key path is not configured")
	}

	certBytes, err := os.ReadFile(cfg.PKI.DeviceCACertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read device ca cert file: %w", err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode device ca certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse device ca certificate: %w", err)
	}

	ecdsaKey, err := loadPrivateKeyFromFile(cfg.PKI.DeviceCAKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("device ca key load: %w", err)
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
	privKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		privKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse key bytes: %w", err)
		}
	}

	ecdsaKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an ECDSA private key")
	}

	return ecdsaKey, nil
}
