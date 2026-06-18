package certs

import (
	_ "embed"
)

//go:embed assets/server-ca.crt
var serverCACertPEM []byte

//go:embed assets/device-ca.crt
var deviceCACertPEM []byte

// ServerCAPEM возвращает байты встроенного сертификата Server CA.
// Используется клиентом для валидации сервера.
func ServerCAPEM() []byte {
	return serverCACertPEM
}

// DeviceCAPEM возвращает байты встроенного сертификата Device CA.
// Используется сервером для mTLS верификации клиентских устройств.
func DeviceCAPEM() []byte {
	return deviceCACertPEM
}
