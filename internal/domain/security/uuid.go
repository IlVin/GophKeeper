package security

import "github.com/google/uuid"

// Каноническое пространство имен (Namespace) проекта GophKeeper для UUID v5.
// Сгенерировано один раз и намертво вшито в крипто-ядро.
var GophKeeperRecordNamespace = uuid.MustParse("a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d")

// DeriveRecordID детерминированно выводит вечный UUID v5 на базе человекочитаемого имени секрета.
// Это гарантирует, что параллельные оффлайн-контейнеры будут генерировать идентичный ID
// для одного и того же секрета, позволяя серверной LWW-логике корректно разрешать конфликты.
func DeriveRecordID(secretName string) string {
	return uuid.NewSHA1(GophKeeperRecordNamespace, []byte(secretName)).String()
}
