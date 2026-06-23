# Инфраструктурный слой PKI сервера (`internal/server/pki`)

Пакет `pki` инкапсулирует в себе логику управления инфраструктурой открытых ключей (Public Key Infrastructure) облачного сервера GophKeeper. Он отвечает за безопасное разделение контекстов хранения ключей, динамическую генерацию TLS-сертификатов вещания на базе кривых NIST P-256 и выпуск индивидуальных mTLS-паспортов устройств по входящим запросам PKCS#10 CSR.

## 📌 Функциональные компоненты подсистемы

1. **`ca.go` (Лоадер Корней Доверия)**: Разделяет хранение публичной части CA (вкомпилирована клиенту и серверу через `go:embed`) и закрытых ключей (загружаются с защищенного диска хоста). Избавлен от MVP-атавизмов деструктивных вызовов `panic`.
2. **`issue.go` (Фабрика Паспортов Контейнеров)**: Валидирует подписи PKCS#10 CSR и подписывает mTLS-сертификаты устройств строго на 30 дней, вшивая `ExtKeyUsageClientAuth` и канонический доменный SAN URI (`urn:gophkeeper:file:deviceID`).
3. **`server_cert.go` (Генератор TLS Вещания)**: Генерирует и подписывает ключом `Server CA` временные TLS-сертификаты сервера на 1 год для работы gRPC-интерфейсов в изолированных оффлайн-контурах, когда Let's Encrypt (`autocert`) недоступен.

---

## 🏗 Архитектура и структура пакета

Пакет полностью автономен от верхних слоев бизнес-логики и gRPC-транспорта, поставляя готовые ASN.1 DER структуры для криптографического ядра:

```mermaid
graph TD
    Handlers["internal-server-transport (gRPC Слой)"] --> Factory["pki (PKI Фабрика)"]
    Factory --> CA["ca.go (Загрузчик Корней Доверия)"]
    Factory --> Issue["issue.go (Выпуск mTLS Паспортов)"]
    Factory --> Server["server-cert.go (Генератор TLS Сессий)"]
    
    CA --> Disk["/etc/gophkeeper/keys/ (Приватные Ключи CA)"]

    style Factory fill:#d4edda,stroke:#28a745,stroke-width:2px
```

---

## 📊 Диаграмма конвейера динамического выпуска паспорта (`IssueDeviceCertificate`)

Пошаговый процесс валидации подписи CSR, защиты от подмены идентичности и динамической генерации 128-битных серийных номеров. Все сообщения экранированы кавычками для корректного отображения в VSCode.

```mermaid
sequenceDiagram
    autonumber
    participant Handler as Хендлер (register.go)
    participant Core as Фабрика (issue.go)
    participant Crypto as Рантайм crypto-x509
    participant OS as Генератор ОС (rand.Reader)

    Handler->>Core: "IssueDeviceCertificate(csrDER, deviceID, caCert, caKey)"
    activate Core
    
    Core->>Crypto: "x509.ParseCertificateRequest(csrDER)"
    Crypto-->>Core: Возврат структуры *x509.CertificateRequest
    
    Core->>Crypto: "csr.CheckSignature() (Верификация подписи CSR)"
    alt Подпись запроса повреждена
        Crypto-->>Core: Ошибка Signature Validation
        Core-->>Handler: gRPC Отказ Unauthenticated
	end

    Note over Core: Защитный ИБ-барьер:<br/>Сверка UUID в теле CSR и в аргументах хендлера
    alt Обнаружено расхождение UUID (Атака Identity Spoofing)
        Core-->>Handler: Жесткий отказ (device identity mismatch)
    end

    Core->>OS: "rand.Int(rand.Reader, 128-bit)"
    OS-->>Core: Случайный серийный номер SerialNumber
    
    Core->>Core: "url.Parse(urn:gophkeeper:file:deviceID)"
    Core->>Core: "Сборка шаблона: ClientAuth, NotAfter = +30 дней"
    
    Core->>Crypto: "x509.CreateCertificate() (Подписание ключом Device CA)"
    Crypto-->>Core: Возврат бинарного x509 DER массива
    
    Core-->>Handler: "Возврат certDER и serialNumber (Success)"
    deactivate Core
```

---

## 🔒 Промышленные ИБ-инварианты пакета

* **Бескомпромиссная RAM-гигиена (Пресечение Memory Dump атак)**: Секретные ключи и промежуточные байтовые буферы (`keyBytes`, `keyBlock.Bytes`) являются главными целями злоумышленников. Промышленная версия пакета защищена каскадными блоками `defer`: при любых аварийных сбоях парсинга или генерации энтропии, сырые ячейки памяти кучи принудительно выжигаются нулями, а секретные компоненты `D` структур `ecdsa.PrivateKey` сбрасываются методом `.SetInt64(0)`.
* **Защита от Identity Spoofing подделок**: Внедрен перекрестный криптографический барьер. Если злоумышленник попытается прислать CSR, подписанный легитимным ключом, но подменит `deviceID` в gRPC-заголовках, фабрика обнаружит несовпадение поля `csr.URIs` с контекстом вызова и заблокирует операцию, предотвращая несанкционированный выпуск паспортов.
* **Централизованный аудит SIEM**: Все факты успешной генерации, серийные номера паспортов и UUID привязанных контейнеров логируются через структурированный `slog.Info`. Сбои парсинга или атаки подмены пишутся в `slog.Warn`/`slog.Error`, поставляя готовые маркеры инцидентов для систем мониторинга информационной безопасности.

---

## 🔬 Юнит-тестирование (`pki_test.go`)

Целостность алгоритмов и барьеры валидации полностью защищены тестами на **100%** (файлы `ca_test.go`, `issue_test.go`, `server_cert_test.go`). 

Тест-кейсы `TestLoadServerCA-FailsIfPathEmpty` и `TestLoadDeviceCA-FailsIfPathEmpty` верифицируют Fail-Fast защиту рантайма от старта с незаданными путями к закрытым ключам CA, а тесты `TestIssueDeviceCertificate-FailsIfInputsInvalid` и `TestGenerateDynamicServerCertificate-FailsIfInputsInvalid` гарантируют тотальную устойчивость криптографических фабрик к передаче пустых параметров, полностью страхуя сервер от паник разыменования нулевых указателей (`nil pointer protection`).
