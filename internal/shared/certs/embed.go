// Package certs инкапсулирует встроенные криптографические сертификаты
// удостоверяющих центров (CA) и методы загрузки пулов доверия.
package certs

import (
	_ "embed"
)

// ServerCACertPEM содержит встроенные в бинарный файл PEM-байты корневого
// сертификата Server CA. Используется клиентом для анкоринга доверия к облаку.
//
//go:embed assets/server-ca.crt
var ServerCACertPEM []byte

// DeviceCACertPEM содержит встроенные в бинарный файл PEM-байты корневого
// сертификата Device CA. Используется для верификации паспортов устройств.
//
//go:embed assets/device-ca.crt
var DeviceCACertPEM []byte

// ServerCAPEM возвращает байты встроенного сертификата Server CA.
// Используется клиентом для валидации сервера.
func ServerCAPEM() []byte {
	return ServerCACertPEM
}

// DeviceCAPEM возвращает байты встроенного сертификата Device CA.
// Используется сервером для mTLS верификации клиентских устройств.
func DeviceCAPEM() []byte {
	return DeviceCACertPEM
}
