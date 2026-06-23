// Package security инкапсулирует криптографическое ядро, алгоритмы деривации,
// контекстной защиты AAD и сериализации протоколов GophKeeper.
package security

import (
	"log/slog"

	"github.com/google/uuid"
)

// Приватная переменная пространства имен (Namespace) проекта GophKeeper для UUID v5.
// Скрыта от внешнего изменения (маленькая буква) для полной защиты рантайма от перезаписи.
var gophkeeperRecordNamespace = uuid.MustParse("a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d")

// DeriveRecordID детерминированно выводит вечный UUID v5 на базе человекочитаемого имени секрета.
//
// Алгоритм гарантирует, что параллельные оффлайн-клиенты сгенерируют идентичный ID
// для одной и той же текстовой записи, позволяя серверной LWW-логике корректно разрешать конфликты.
func DeriveRecordID(secretName string) string {
	slog.Debug("Executing deterministic UUID v5 derivation from record name", "name", secretName)

	// Генерация UUID v5 на базе SHA-1 хеширования по спецификации RFC 4122
	derivedUUID := uuid.NewSHA1(gophkeeperRecordNamespace, []byte(secretName))

	return derivedUUID.String()
}
